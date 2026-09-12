// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.35;

import {Test} from "forge-std/Test.sol";

import {ILoanRouterV2} from "src/interfaces/ILoanRouterV2.sol";
import {LoanLogicV2} from "src/LoanLogicV2.sol";

/**
 * @title StakedUSDai Loan-Router Accrual Attack
 * @notice A genuinely fresh, cross-repo composability attack: StakedUSDai (in
 * usdai-contracts) tracks a SHARED, per-currency-token "lazy aggregate"
 * interest accrual across ALL loans it is a lender on, via
 * LoanRouterPositionManagerLogic._accrue(). This accrued value directly
 * feeds StakedUSDai._assets(OPTIMISTIC), which drives sUSDai's share price
 * via convertToShares/convertToAssets.
 *
 * Attacker goal: find a sequence of loan-lifecycle events (origination,
 * partial repayment, full repayment, refinance - all interleaved across
 * MULTIPLE concurrent loans sharing one currency token's accrual bucket)
 * that makes the on-chain aggregate accrued value drift away from the
 * ground-truth sum of each individual loan's own linear accrual since its
 * last touch. Any drift is directly exploitable: inflate it and redeem
 * sUSDai shares at an inflated NAV, or (less obviously) silently erase a
 * legitimate depositor's real accrued yield.
 *
 * Method: since StakedUSDai's hooks (onLoanOriginated/onLoanRepayment/
 * onLoanRefinanced/onLoanLiquidated/onLoanCollateralLiquidated) are gated
 * ONLY by `msg.sender == loanRouter` (LoanRouterPositionManagerLogic.
 * _validateHookContext), and take fully caller-supplied LoanTermsV2/amount
 * parameters, this test operates directly on the REAL deployed sUSDai
 * contract on a forked mainnet, pranking as the REAL LoanRouterV2 address
 * (exactly matching what the real router would do), driving fully
 * synthetic "shadow loans" through the hooks and comparing the contract's
 * own reported accrued value against an independently-computed,
 * dead-simple ground-truth ledger after every action.
 */
interface IStakedUSDaiLoanRouterHooksTest {
    function onLoanOriginated(
        ILoanRouterV2.LoanTermsV2 calldata loanTerms,
        bytes32 loanTermsHash,
        uint8 trancheIndex
    ) external;

    function onLoanRepayment(
        ILoanRouterV2.LoanTermsV2 calldata loanTerms,
        bytes32 loanTermsHash,
        uint8 trancheIndex,
        uint256 loanBalance,
        uint256 principal,
        uint256 interest,
        uint256 prepay
    ) external;

    function onLoanRefinanced(
        ILoanRouterV2.LoanTermsV2 calldata oldLoanTerms,
        ILoanRouterV2.LoanTermsV2 calldata newLoanTerms,
        bytes32 oldLoanTermsHash,
        bytes32 newLoanTermsHash,
        uint8 trancheIndex,
        uint256 cashOut,
        uint256 cashIn
    ) external;

    function onLoanLiquidated(
        ILoanRouterV2.LoanTermsV2 calldata loanTerms,
        bytes32 loanTermsHash,
        uint8 trancheIndex
    ) external;
}

interface IStakedUSDaiViewsTest {
    function loanRouterBalances() external view returns (uint256 pendingLoanBalance, uint256 accruedLoanInterest);
}

contract StakedUSDaiAccrualAttackTest is Test {
    address internal constant SUSDAI = 0x0B2b2B2076d95dda7817e785989fE353fe955ef9;
    address internal constant USDAI = 0x0A1a1A107E45b7Ced86833863f482BC5f4ed82EF;
    address internal constant LOAN_ROUTER_V2 = 0x1C2ED170de32846316784c4fd58A5e3C7563E12f;
    address internal constant COLLATERAL_NFT = address(0xC0117A7E7A1);

    uint256 internal constant FIXED_POINT_SCALE = 1e18;

    struct ShadowLoan {
        bytes32 hash;
        uint256 rate; // accrualRate = trancheRate * pendingBalance, frozen at last touch
        uint256 pendingBalance;
        uint64 lastTouch;
        bool open;
    }

    ShadowLoan[] internal shadowLoans;
    uint256 internal backgroundRate; // EXACT real on-chain accrual.rate at t0 (read from storage, not estimated)
    uint256 internal baselineAccruedRaw; // EXACT real on-chain accrual.accrued at t0 (read from storage)
    uint64 internal baselineTimestamp; // EXACT real on-chain accrual.timestamp at t0 (read from storage)
    uint64 internal t0;

    /*------------------------------------------------------------------------*/
    /* Direct storage access to StakedUSDai's namespaced `Loans` struct -
     * avoids ANY estimation/calibration of the real background accrual rate,
     * which proved unreliable (a first attempt at estimating it via a
     * before/after-warp read of loanRouterBalances() produced small but real
     * drift that could not be cleanly distinguished from a genuine contract
     * bug without this). Layout, derived from the verified deployed source:
     *
     *   bytes32 LOANS_STORAGE_LOCATION = keccak256(...) & ~0xff;  (ERC-7201)
     *   struct Loans {
     *       EnumerableSet.AddressSet currencyTokens;      // slots +0, +1
     *       mapping(address => Repayment) repaymentBalances; // slot +2
     *       mapping(address => uint256) pendingBalances;     // slot +3
     *       mapping(address => Accrual) interestAccruals;    // slot +4
     *       mapping(bytes32 => Loan) loan;                   // slot +5
     *   }
     *   struct Accrual { uint256 accrued; uint256 rate; uint64 timestamp; }
     *
     * EnumerableSet.AddressSet wraps a Set{ bytes32[] _values; mapping(...)
     * _positions; } - confirmed from the actual verified EnumerableSet.sol
     * source (OpenZeppelin, unchanged layout for years): exactly 2 slots.
     */
    bytes32 internal constant LOANS_STORAGE_LOCATION =
        0xeedf9bea8709bd441d5da250df505e80fc82bec74f9f1df28edf19fa1ed4bd00;
    uint256 internal constant INTEREST_ACCRUALS_SLOT_OFFSET = 4;

    function _accrualEntrySlot(
        address token
    ) internal pure returns (bytes32) {
        bytes32 mappingBaseSlot = bytes32(uint256(LOANS_STORAGE_LOCATION) + INTEREST_ACCRUALS_SLOT_OFFSET);
        return keccak256(abi.encode(token, mappingBaseSlot));
    }

    function _readAccrual(
        address token
    ) internal view returns (uint256 accrued, uint256 rate, uint64 timestamp) {
        bytes32 base = _accrualEntrySlot(token);
        accrued = uint256(vm.load(SUSDAI, base));
        rate = uint256(vm.load(SUSDAI, bytes32(uint256(base) + 1)));
        timestamp = uint64(uint256(vm.load(SUSDAI, bytes32(uint256(base) + 2))));
    }

    function setUp() public {
        vm.createSelectFork(vm.envString("ARBITRUM_RPC_URL"));

        (uint256 accrued0, uint256 rate0, uint64 timestamp0) = _readAccrual(USDAI);

        // Sanity: independently confirm our derived slot actually matches what the public
        // view function reports (both should describe the same real, pre-existing state).
        (, uint256 accruedViaView) = IStakedUSDaiViewsTest(SUSDAI).loanRouterBalances();
        uint256 accruedViaStorage = (accrued0 + rate0 * (block.timestamp - timestamp0)) / FIXED_POINT_SCALE;
        require(accruedViaStorage == accruedViaView, "storage slot derivation mismatch - aborting");

        baselineAccruedRaw = accrued0;
        backgroundRate = rate0;
        baselineTimestamp = timestamp0;
        t0 = uint64(block.timestamp);
    }

    function _buildLoanTerms(
        uint256 rate,
        uint256 principal
    ) internal view returns (ILoanRouterV2.LoanTermsV2 memory terms) {
        ILoanRouterV2.TrancheSpec[] memory tranches = new ILoanRouterV2.TrancheSpec[](1);
        tranches[0] = ILoanRouterV2.TrancheSpec({lender: SUSDAI, amount: principal, rate: rate});

        terms = ILoanRouterV2.LoanTermsV2({
            expiration: type(uint64).max,
            borrower: address(0xB0770B0770B),
            currencyToken: USDAI,
            collateralToken: COLLATERAL_NFT,
            repaymentSpec: ILoanRouterV2.RepaymentSpec({day: 1, totalDurationDays: 365, timezoneOffsetSeconds: 0}),
            interestRateSpec: ILoanRouterV2.InterestRateSpec({model: address(0x1), options: ""}),
            collateralTokenIds: new uint256[](0),
            trancheSpecs: tranches,
            feeSpecs: new ILoanRouterV2.FeeSpec[](0),
            approvalAddresses: new address[](0),
            options: abi.encode(rate, principal, block.timestamp, gasleft())
        });
    }

    function _originate(uint256 rate, uint256 principal) internal returns (uint256 idx) {
        ILoanRouterV2.LoanTermsV2 memory terms = _buildLoanTerms(rate, principal);
        bytes32 loanHash = LoanLogicV2.hashLoanTerms(abi.encode(terms));

        vm.prank(LOAN_ROUTER_V2);
        IStakedUSDaiLoanRouterHooksTest(SUSDAI).onLoanOriginated(terms, loanHash, 0);

        shadowLoans.push(
            ShadowLoan({hash: loanHash, rate: rate * principal, pendingBalance: principal, lastTouch: uint64(block.timestamp), open: true})
        );
        return shadowLoans.length - 1;
    }

    // Tracks the original (rate, principal) pair per loan so we can rebuild an identical
    // LoanTermsV2 struct later (LoanTermsV2 itself isn't stored on-chain for us to re-read).
    struct OriginalParams {
        uint256 rate;
        uint256 principal;
    }

    OriginalParams[] internal originals;

    function _originateTracked(uint256 rate, uint256 principal) internal returns (uint256 idx) {
        idx = _originate(rate, principal);
        originals.push(OriginalParams({rate: rate, principal: principal}));
    }

    function _repayTracked(uint256 idx, uint256 repayPrincipal, bool full) internal {
        OriginalParams memory p = originals[idx];
        ILoanRouterV2.LoanTermsV2 memory terms = _buildLoanTerms(p.rate, p.principal);
        bytes32 loanHash = LoanLogicV2.hashLoanTerms(abi.encode(terms));

        ShadowLoan storage loan = shadowLoans[idx];
        uint256 newPending = full ? 0 : loan.pendingBalance - repayPrincipal;

        vm.prank(LOAN_ROUTER_V2);
        IStakedUSDaiLoanRouterHooksTest(SUSDAI).onLoanRepayment(
            terms, loanHash, 0, newPending, repayPrincipal, 0, 0
        );

        loan.pendingBalance = newPending;
        loan.rate = p.rate * newPending;
        loan.lastTouch = uint64(block.timestamp);
        if (newPending == 0) loan.open = false;
    }

    function _groundTruthAccrued() internal view returns (uint256 total) {
        total = baselineAccruedRaw + backgroundRate * (block.timestamp - baselineTimestamp);
        for (uint256 i; i < shadowLoans.length; i++) {
            if (shadowLoans[i].open) {
                total += shadowLoans[i].rate * (block.timestamp - shadowLoans[i].lastTouch);
            }
        }
    }

    function _actualAccrued() internal view returns (uint256) {
        (, uint256 accrued) = IStakedUSDaiViewsTest(SUSDAI).loanRouterBalances();
        return accrued * FIXED_POINT_SCALE;
    }

    function _assertGroundTruthMatches(
        string memory label
    ) internal {
        uint256 expected = _groundTruthAccrued();
        uint256 actual = _actualAccrued();
        // backgroundRate/baselineAccruedRaw/baselineTimestamp are now EXACT values read directly
        // from storage (no calibration/estimation), so the only remaining source of expected
        // slack is loanRouterBalances()'s own single FIXED_POINT_SCALE integer-division
        // truncation on read (strictly < FIXED_POINT_SCALE). A small safety margin is kept for
        // truncation in intermediate per-loan arithmetic across up to a handful of loans.
        uint256 tolerance = FIXED_POINT_SCALE * 10;
        emit log_named_string("check", label);
        emit log_named_uint("  expected (ground truth)", expected);
        emit log_named_uint("  actual (on-chain)      ", actual);
        assertApproxEqAbs(actual, expected, tolerance, string.concat("ACCRUAL DRIFT at: ", label));
    }

    /* Attack 1: two concurrent loans, interleaved full repayment, checking for the
       "loan A's entire lifetime accrual vanishes/duplicates" class of bug. */
    function test__Attack_TwoConcurrentLoans_InterleavedRepayment() public {
        uint256 a = _originateTracked(10, 1_000_000 ether);
        _assertGroundTruthMatches("after origin A");

        vm.warp(block.timestamp + 10 days);
        uint256 b = _originateTracked(3, 2_000_000 ether);
        _assertGroundTruthMatches("after origin B (+10d)");

        vm.warp(block.timestamp + 20 days);
        _repayTracked(a, 1_000_000 ether, true);
        _assertGroundTruthMatches("after full repay A (+20d)");

        vm.warp(block.timestamp + 15 days);
        _repayTracked(b, 2_000_000 ether, true);
        _assertGroundTruthMatches("after full repay B (+15d)");
    }

    /* Attack 2: three loans, partial repayments changing rate mid-life, plus a loan
       originated and repaid within the SAME block (zero elapsed time) to probe
       division-by-zero / zero-duration edge cases in the lazy accrual formula. */
    function test__Attack_ThreeLoans_PartialRepaysAndZeroDurationLoan() public {
        uint256 a = _originateTracked(7, 500_000 ether);
        vm.warp(block.timestamp + 5 days);

        uint256 b = _originateTracked(11, 750_000 ether);
        // Zero-duration loan: originate and fully repay in the same timestamp.
        uint256 c = _originateTracked(1000, 1 ether);
        _repayTracked(c, 1 ether, true);
        _assertGroundTruthMatches("after zero-duration loan C open+close");

        vm.warp(block.timestamp + 8 days);
        _repayTracked(a, 200_000 ether, false); // partial repay, rate changes
        _assertGroundTruthMatches("after partial repay A (+8d)");

        vm.warp(block.timestamp + 12 days);
        _repayTracked(a, 300_000 ether, true); // close out remainder of A
        _assertGroundTruthMatches("after final repay A (+12d)");

        vm.warp(block.timestamp + 30 days);
        _repayTracked(b, 750_000 ether, true);
        _assertGroundTruthMatches("after full repay B (+30d)");
    }

    /* Attack 3: many loans opened back-to-back at the SAME timestamp (zero gap between
       originations), then all closed in reverse order - stress-tests whether the
       "subtract this loan's full-lifetime rate contribution" correction ever double-counts
       or under-counts when many loans share identical touch timestamps. */
    function test__Attack_ManySimultaneousOriginations_ReverseOrderClose() public {
        uint256[] memory idx = new uint256[](6);
        for (uint256 i; i < 6; i++) {
            idx[i] = _originateTracked((i + 1) * 2, (i + 1) * 100_000 ether);
        }
        _assertGroundTruthMatches("after 6 simultaneous originations");

        vm.warp(block.timestamp + 17 days);
        _assertGroundTruthMatches("after +17d, no touches yet");

        for (uint256 i = 6; i > 0; i--) {
            uint256 loanIdx = idx[i - 1];
            OriginalParams memory p = originals[loanIdx];
            _repayTracked(loanIdx, p.principal, true);
            vm.warp(block.timestamp + 3 days);
            _assertGroundTruthMatches(string.concat("after closing loan (reverse order) #", vm.toString(i)));
        }
    }
}
