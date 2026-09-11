// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.35;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {RouterFixture} from "./helpers/RouterFixture.sol";
import {ILoanRouterV2} from "src/interfaces/ILoanRouterV2.sol";
import {LoanLogicV2} from "src/LoanLogicV2.sol";

/**
 * @title Combined Stress Attack — three simultaneous attacker angles driven
 * through Foundry's invariant fuzzer against the SAME live router deployment
 * in a single campaign, instead of three isolated tests. The fuzzer freely
 * interleaves calls across all three handlers below (pause toggling,
 * cross-loan repayments, and over-approved repay attempts can all land back
 * to back, in any order, any number of times), so any bug that only shows up
 * from unexpected call ORDERING across these three surfaces — not just from
 * hammering one surface in isolation — has a real chance to surface here.
 *
 * Handler A — PauseRaceHandler: races admin pause()/unpause() calls against
 * borrower repay() attempts. Attacker goal: get a repay to go through while
 * the router is supposed to be paused (bypassing an emergency stop).
 *
 * Handler B — CrossLoanIsolationHandler: drives TWO independently originated
 * loans (same borrower, distinct collateral/hash) through interleaved
 * repayments. Attacker goal: find a shared-storage or accounting bleed where
 * repaying loan A mutates loan B's on-chain state (status/repaymentCount/
 * balance), which would mean loan storage isn't properly keyed per-hash.
 *
 * Handler C — OverpayExcessPullHandler: repeatedly repays with a `amount`
 * argument far larger than the quoted amount actually owed (simulating a
 * confused/malicious frontend or an attacker probing whether passing a huge
 * `amount` lets the router pull more than what's actually owed). Attacker
 * goal: get the router to transferFrom() more currency token than the
 * quoted repayment — i.e., extract value beyond what borrower legitimately
 * owes at that moment.
 */
contract PauseRaceHandler {
    CombinedStressAttackTest internal immutable fixture_;
    ILoanRouterV2 internal immutable router;
    address internal immutable borrower;
    ILoanRouterV2.LoanTermsV2 internal loanTerms;

    uint256 public pauseToggleCount;
    uint256 public repayAttemptsWhilePaused;
    uint256 public repaySucceededWhilePaused; // MUST stay 0 — the core finding target

    constructor(
        CombinedStressAttackTest fixture,
        address router_,
        ILoanRouterV2.LoanTermsV2 memory terms,
        address borrower_
    ) {
        fixture_ = fixture;
        router = ILoanRouterV2(router_);
        loanTerms = terms;
        borrower = borrower_;
    }

    /// @notice Admin randomly flips pause state (no-ops swallowed if already
    /// in that state — that's a legitimate revert, not part of what we test).
    function togglePause(
        uint256 seed
    ) external {
        fixture_.setPaused(seed % 2 == 0);
        pauseToggleCount++;
    }

    /// @notice Borrower attempts a real repay regardless of pause state —
    /// checks paused() atomically right before the call, then attempts it.
    function attemptRepayRegardlessOfPause(
        uint256 timeSeed
    ) external {
        uint64 targetTimestamp = uint64(block.timestamp + (timeSeed % 400 days));
        fixture_.warpForward(targetTimestamp);

        bool wasPausedBeforeAttempt = fixture_.isPaused();

        (uint256 principal, uint256 interest, uint256 fee) = router.quote(loanTerms);
        uint256 totalDue = principal + interest + fee;
        if (totalDue == 0) return;

        bool succeeded = fixture_.repayAsBorrowerAmount(loanTerms, totalDue);

        if (wasPausedBeforeAttempt) {
            repayAttemptsWhilePaused++;
            if (succeeded) repaySucceededWhilePaused++;
        }
    }
}

contract CrossLoanIsolationHandler {
    CombinedStressAttackTest internal immutable fixture_;
    ILoanRouterV2 internal immutable router;
    address internal immutable borrower;
    ILoanRouterV2.LoanTermsV2 internal loanA;
    ILoanRouterV2.LoanTermsV2 internal loanB;
    bytes32 internal immutable hashA;
    bytes32 internal immutable hashB;

    uint256 public repaysOnA;
    uint256 public repaysOnB;
    uint256 public crossContaminationDetections; // MUST stay 0 — the core finding target

    constructor(
        CombinedStressAttackTest fixture,
        address router_,
        ILoanRouterV2.LoanTermsV2 memory termsA,
        ILoanRouterV2.LoanTermsV2 memory termsB,
        address borrower_
    ) {
        fixture_ = fixture;
        router = ILoanRouterV2(router_);
        loanA = termsA;
        loanB = termsB;
        borrower = borrower_;
        hashA = LoanLogicV2.hashLoanTerms(abi.encode(termsA));
        hashB = LoanLogicV2.hashLoanTerms(abi.encode(termsB));
    }

    function repayLoanA(
        uint256 timeSeed
    ) external {
        _repayTargetCheckingOther(loanA, hashB, timeSeed);
        repaysOnA++;
    }

    function repayLoanB(
        uint256 timeSeed
    ) external {
        _repayTargetCheckingOther(loanB, hashA, timeSeed);
        repaysOnB++;
    }

    /// @notice Snapshot the OTHER loan's on-chain state, repay the target
    /// loan, then re-read the other loan's state — any drift means the two
    /// loans' storage isn't properly isolated by hash.
    function _repayTargetCheckingOther(
        ILoanRouterV2.LoanTermsV2 memory target,
        bytes32 otherHash,
        uint256 timeSeed
    ) internal {
        uint64 targetTimestamp = uint64(block.timestamp + (timeSeed % 400 days));
        fixture_.warpForward(targetTimestamp);

        (ILoanRouterV2.LoanStatus statusBefore, uint16 countBefore,, uint256 balanceBefore) =
            router.loanState(otherHash);

        (uint256 principal, uint256 interest, uint256 fee) = router.quote(target);
        uint256 totalDue = principal + interest + fee;
        if (totalDue > 0) {
            fixture_.repayAsBorrowerAmount(target, totalDue);
        }

        (ILoanRouterV2.LoanStatus statusAfter, uint16 countAfter,, uint256 balanceAfter) = router.loanState(otherHash);

        if (statusBefore != statusAfter || countBefore != countAfter || balanceBefore != balanceAfter) {
            crossContaminationDetections++;
        }
    }
}

contract OverpayExcessPullHandler {
    CombinedStressAttackTest internal immutable fixture_;
    ILoanRouterV2 internal immutable router;
    address internal immutable borrower;
    ILoanRouterV2.LoanTermsV2 internal loanTerms;

    uint256 public overpayAttempts;
    uint256 public excessPullDetections; // MUST stay 0 — the core finding target

    /// Rounding tolerance: quote() rounds each of principal/interest/fee UP
    /// individually, but repay() unscales their combined sum in one shot —
    /// summing three independently-rounded-up components can legitimately
    /// read up to a few wei higher than what repay() actually pulls. This is
    /// pure benign rounding slack, not a bug, and is bounded tightly so a
    /// real excess-pull bug (which would show up as thousands+ wei, or a
    /// meaningful percentage) is never masked by it.
    uint256 internal constant ROUNDING_TOLERANCE_WEI = 8;

    constructor(
        CombinedStressAttackTest fixture,
        address router_,
        ILoanRouterV2.LoanTermsV2 memory terms,
        address borrower_
    ) {
        fixture_ = fixture;
        router = ILoanRouterV2(router_);
        loanTerms = terms;
        borrower = borrower_;
    }

    /// @notice Deliberately approve/attempt repayment with an `amount` far
    /// larger than what's actually quoted/owed, then verify the router only
    /// ever pulls the true owed amount (plus benign rounding slack) from the
    /// borrower — never the inflated `amount` itself.
    function attemptOverpay(
        uint256 timeSeed,
        uint256 surplusSeed
    ) external {
        uint64 targetTimestamp = uint64(block.timestamp + (timeSeed % 400 days));
        fixture_.warpForward(targetTimestamp);

        (uint256 principal, uint256 interest, uint256 fee) = router.quote(loanTerms);
        uint256 quoted = principal + interest + fee;
        if (quoted == 0) return;

        uint256 surplus = 1 + (surplusSeed % 1_000_000 ether);
        uint256 attemptAmount = quoted + surplus;

        uint256 routerBalanceBefore = IERC20(loanTerms.currencyToken).balanceOf(address(router));
        overpayAttempts++;

        bool succeeded = fixture_.repayAsBorrowerAmount(loanTerms, attemptAmount);
        if (!succeeded) return;

        uint256 routerBalanceAfter = IERC20(loanTerms.currencyToken).balanceOf(address(router));
        uint256 actualPulled = routerBalanceAfter - routerBalanceBefore;

        if (actualPulled > quoted + ROUNDING_TOLERANCE_WEI) {
            excessPullDetections++;
        }
    }
}

contract CombinedStressAttackTest is RouterFixture {
    PauseRaceHandler internal pauseHandler;
    CrossLoanIsolationHandler internal crossLoanHandler;
    OverpayExcessPullHandler internal overpayHandler;

    ILoanRouterV2.LoanTermsV2 internal loanA;
    ILoanRouterV2.LoanTermsV2 internal loanB;

    function setUp() public override {
        super.setUp();

        /* Originate two independent loans up front (same fixed variant/
         * timestamp, distinct collateral token IDs => distinct hashes) so
         * every handler below shares a consistent, already-active starting
         * state before the fuzzer starts interleaving calls across them. */
        loanA = originateDefault();
        loanB = originateConfigured(_defaultConfig());

        pauseHandler = new PauseRaceHandler(this, address(router), loanA, users.borrower);
        crossLoanHandler = new CrossLoanIsolationHandler(this, address(router), loanA, loanB, users.borrower);
        overpayHandler = new OverpayExcessPullHandler(this, address(router), loanB, users.borrower);

        targetContract(address(pauseHandler));
        targetContract(address(crossLoanHandler));
        targetContract(address(overpayHandler));
    }

    /*------------------------------------------------------------------------*/
    /* Fixture callbacks the handlers drive (vm cheatcodes + role pranks
     * only live on a Test-derived contract, so handlers route through here
     * rather than holding vm access themselves). */
    /*------------------------------------------------------------------------*/

    function warpForward(
        uint64 timestamp
    ) external {
        vm.warp(timestamp);
    }

    function isPaused() external view returns (bool) {
        return router.paused();
    }

    function setPaused(
        bool shouldBePaused
    ) external {
        vm.startPrank(users.admin);
        if (shouldBePaused) {
            try router.pause() { } catch { }
        } else {
            try router.unpause() { } catch { }
        }
        vm.stopPrank();
    }

    function repayAsBorrowerAmount(
        ILoanRouterV2.LoanTermsV2 memory terms,
        uint256 amount
    ) external returns (bool success) {
        deal(terms.currencyToken, users.borrower, amount + 1e24);
        vm.startPrank(users.borrower);
        IERC20(terms.currencyToken).approve(address(router), amount);
        try router.repay(terms, amount) {
            success = true;
        } catch {
            success = false;
        }
        vm.stopPrank();
    }

    /*------------------------------------------------------------------------*/
    /* Invariants — every one of these must hold no matter what order or how
     * many times the fuzzer interleaves calls across all three handlers. */
    /*------------------------------------------------------------------------*/

    /// @notice A repay() must never succeed while the router is paused.
    function invariant_NoRepaySucceedsWhilePaused() public view {
        assert(pauseHandler.repaySucceededWhilePaused() == 0);
    }

    /// @notice Repaying one loan must never mutate the other loan's status,
    /// repayment count, or scaled balance — loan storage must stay isolated
    /// per loan-terms hash even under heavy interleaved multi-loan traffic.
    function invariant_NoCrossLoanContamination() public view {
        assert(crossLoanHandler.crossContaminationDetections() == 0);
    }

    /// @notice A caller passing an inflated `amount` far beyond what's
    /// actually quoted/owed must never cause the router to pull more than
    /// the true owed amount (plus benign wei-level rounding slack).
    function invariant_RepayNeverPullsMoreThanQuoted() public view {
        assert(overpayHandler.excessPullDetections() == 0);
    }

    /// @notice Sanity: the attack surfaces were actually exercised (a
    /// trivially-passing invariant over zero real calls would be worthless).
    function invariant_HandlersWereActuallyExercised() public view {
        assert(
            pauseHandler.pauseToggleCount() > 0 || crossLoanHandler.repaysOnA() > 0
                || overpayHandler.overpayAttempts() > 0
        );
    }
}
