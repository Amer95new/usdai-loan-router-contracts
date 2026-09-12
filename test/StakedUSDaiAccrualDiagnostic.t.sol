// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.35;

import {Test} from "forge-std/Test.sol";

import {ILoanRouterV2} from "src/interfaces/ILoanRouterV2.sol";
import {LoanLogicV2} from "src/LoanLogicV2.sol";

/**
 * @title StakedUSDai Accrual Diagnostic - Minimal Isolation
 * @notice Isolates the EXACT single hook call that produces drift found by
 * StakedUSDaiAccrualAttack.t.sol, by comparing RAW on-chain storage values
 * (accrual.accrued/.rate/.timestamp) directly against the LITERAL formula
 * from LoanRouterPositionManagerLogic._accrue()/loanRepayment(), reproduced
 * here term-for-term from the verified deployed source - not an
 * independently-derived "ground truth" model, to remove any possibility of
 * ambiguity about which side is wrong. Every comparison is done in raw,
 * unscaled storage units with zero division, so there is no rounding
 * tolerance needed at all - an exact match is the only correct outcome.
 */
interface IStakedUSDaiHooksDiag {
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
}

contract StakedUSDaiAccrualDiagnosticTest is Test {
    address internal constant SUSDAI = 0x0B2b2B2076d95dda7817e785989fE353fe955ef9;
    address internal constant USDAI = 0x0A1a1A107E45b7Ced86833863f482BC5f4ed82EF;
    address internal constant LOAN_ROUTER_V2 = 0x1C2ED170de32846316784c4fd58A5e3C7563E12f;

    bytes32 internal constant LOANS_STORAGE_LOCATION =
        0xeedf9bea8709bd441d5da250df505e80fc82bec74f9f1df28edf19fa1ed4bd00;
    uint256 internal constant INTEREST_ACCRUALS_SLOT_OFFSET = 4;

    function _accrualEntrySlot(
        address token
    ) internal pure returns (bytes32) {
        bytes32 mappingBaseSlot = bytes32(uint256(LOANS_STORAGE_LOCATION) + INTEREST_ACCRUALS_SLOT_OFFSET);
        return keccak256(abi.encode(token, mappingBaseSlot));
    }

    function _readAccrual() internal view returns (uint256 accrued, uint256 rate, uint64 timestamp) {
        bytes32 base = _accrualEntrySlot(USDAI);
        accrued = uint256(vm.load(SUSDAI, base));
        rate = uint256(vm.load(SUSDAI, bytes32(uint256(base) + 1)));
        timestamp = uint64(uint256(vm.load(SUSDAI, bytes32(uint256(base) + 2))));
    }

    function _buildLoanTerms(
        uint256 rate,
        uint256 principal,
        uint256 salt
    ) internal view returns (ILoanRouterV2.LoanTermsV2 memory terms) {
        ILoanRouterV2.TrancheSpec[] memory tranches = new ILoanRouterV2.TrancheSpec[](1);
        tranches[0] = ILoanRouterV2.TrancheSpec({lender: SUSDAI, amount: principal, rate: rate});

        terms = ILoanRouterV2.LoanTermsV2({
            expiration: type(uint64).max,
            borrower: address(0xB0770B0770B),
            currencyToken: USDAI,
            collateralToken: address(0xC0117A7E7A1),
            repaymentSpec: ILoanRouterV2.RepaymentSpec({day: 1, totalDurationDays: 365, timezoneOffsetSeconds: 0}),
            interestRateSpec: ILoanRouterV2.InterestRateSpec({model: address(0x1), options: ""}),
            collateralTokenIds: new uint256[](0),
            trancheSpecs: tranches,
            feeSpecs: new ILoanRouterV2.FeeSpec[](0),
            approvalAddresses: new address[](0),
            options: abi.encode(salt)
        });
    }

    function setUp() public {
        vm.createSelectFork(vm.envString("ARBITRUM_RPC_URL"));
    }

    /**
     * @notice Minimal 2-touch isolation: originate ONE loan, warp, repay it fully.
     * Every intermediate raw storage value is checked against the literal source
     * formula, term by term, so any drift is pinned to an exact step.
     */
    function test__Diagnostic_SingleLoan_OriginateThenRepay() public {
        (uint256 accrued0, uint256 rate0, uint64 ts0) = _readAccrual();
        emit log_named_uint("accrued0", accrued0);
        emit log_named_uint("rate0", rate0);
        emit log_named_uint("ts0", ts0);

        uint256 loanRate = 10;
        uint256 loanPrincipal = 1_000_000 ether;
        uint256 loanAccrualRate = loanRate * loanPrincipal;

        ILoanRouterV2.LoanTermsV2 memory terms = _buildLoanTerms(loanRate, loanPrincipal, 1);
        bytes32 loanHash = LoanLogicV2.hashLoanTerms(abi.encode(terms));

        vm.prank(LOAN_ROUTER_V2);
        IStakedUSDaiHooksDiag(SUSDAI).onLoanOriginated(terms, loanHash, 0);

        (uint256 accrued1, uint256 rate1, uint64 ts1) = _readAccrual();
        emit log_named_uint("accrued1", accrued1);
        emit log_named_uint("rate1", rate1);
        emit log_named_uint("ts1", ts1);

        // Origination formula: _accrue(accrual, 0, 0, 0) then accrual.rate += loanAccrualRate.
        // Since oldAccrualRate/timestamp/lastRepaymentTimestamp are all 0, the subtracted term
        // is 0 * (0 - 0) = 0, so accrued should only grow by rate0*(ts1-ts0).
        uint256 expectedAccrued1 = accrued0 + rate0 * (ts1 - ts0);
        uint256 expectedRate1 = rate0 + loanAccrualRate;
        assertEq(accrued1, expectedAccrued1, "DRIFT at origination: accrued mismatch");
        assertEq(rate1, expectedRate1, "DRIFT at origination: rate mismatch");
        assertEq(ts1, block.timestamp, "DRIFT at origination: timestamp mismatch");

        uint256 WARP = 10 days;
        vm.warp(block.timestamp + WARP);

        vm.prank(LOAN_ROUTER_V2);
        IStakedUSDaiHooksDiag(SUSDAI).onLoanRepayment(terms, loanHash, 0, 0, loanPrincipal, 0, 0);

        (uint256 accrued2, uint256 rate2, uint64 ts2) = _readAccrual();
        emit log_named_uint("accrued2", accrued2);
        emit log_named_uint("rate2", rate2);
        emit log_named_uint("ts2", ts2);

        // Repayment formula (from LoanRouterPositionManagerLogic.loanRepayment / _accrue):
        //   _accrue(accrual, loan.accrualRate, ts2, loan.lastRepaymentTimestamp=ts1):
        //     accrued += rate1*(ts2-ts1) - loanAccrualRate*(ts2-ts1)
        //   then: accrual.rate = rate1 + newAccrualRate(=0, fully repaid) - loanAccrualRate
        uint256 elapsed = ts2 - ts1;
        uint256 expectedAccrued2 = accrued1 + rate1 * elapsed - loanAccrualRate * elapsed;
        uint256 expectedRate2 = rate1 - loanAccrualRate;

        emit log_named_uint("expectedAccrued2", expectedAccrued2);
        emit log_named_uint("expectedRate2", expectedRate2);

        assertEq(rate2, expectedRate2, "DRIFT at repayment: rate mismatch");
        assertEq(accrued2, expectedAccrued2, "DRIFT at repayment: accrued mismatch (THIS IS THE BUG IF IT FAILS)");
    }

    /**
     * @notice Same isolation, but the SECOND touch is an origination (loan B) instead of a
     * repayment - matching the exact shape of the "after origin B (+10d)" drift found in
     * StakedUSDaiAccrualAttack.t.sol. loanOriginated's _accrue call always uses
     * (oldAccrualRate=0, timestamp=0, lastRepaymentTimestamp=0), so the subtracted term is
     * always 0*(0-0)=0 regardless of any other loan's state - this should be the simplest
     * possible accrual step with no subtraction-term interaction at all.
     */
    function test__Diagnostic_TwoLoans_OriginateThenOriginate() public {
        (uint256 accrued0, uint256 rate0, uint64 ts0) = _readAccrual();

        uint256 rateA = 10;
        uint256 principalA = 1_000_000 ether;
        ILoanRouterV2.LoanTermsV2 memory termsA = _buildLoanTerms(rateA, principalA, 1);
        bytes32 hashA = LoanLogicV2.hashLoanTerms(abi.encode(termsA));

        vm.prank(LOAN_ROUTER_V2);
        IStakedUSDaiHooksDiag(SUSDAI).onLoanOriginated(termsA, hashA, 0);

        (uint256 accrued1, uint256 rate1, uint64 ts1) = _readAccrual();
        assertEq(accrued1, accrued0 + rate0 * (ts1 - ts0), "DRIFT at loan A origination: accrued mismatch");
        assertEq(rate1, rate0 + rateA * principalA, "DRIFT at loan A origination: rate mismatch");

        vm.warp(block.timestamp + 10 days);

        uint256 rateB = 3;
        uint256 principalB = 2_000_000 ether;
        ILoanRouterV2.LoanTermsV2 memory termsB = _buildLoanTerms(rateB, principalB, 2);
        bytes32 hashB = LoanLogicV2.hashLoanTerms(abi.encode(termsB));

        vm.prank(LOAN_ROUTER_V2);
        IStakedUSDaiHooksDiag(SUSDAI).onLoanOriginated(termsB, hashB, 0);

        (uint256 accrued2, uint256 rate2, uint64 ts2) = _readAccrual();

        uint256 elapsed = ts2 - ts1;
        uint256 expectedAccrued2 = accrued1 + rate1 * elapsed; // no subtraction term for origination
        uint256 expectedRate2 = rate1 + rateB * principalB;

        emit log_named_uint("accrued1", accrued1);
        emit log_named_uint("rate1", rate1);
        emit log_named_uint("elapsed", elapsed);
        emit log_named_uint("accrued2 (actual)", accrued2);
        emit log_named_uint("expectedAccrued2", expectedAccrued2);

        assertEq(rate2, expectedRate2, "DRIFT at loan B origination: rate mismatch");
        assertEq(accrued2, expectedAccrued2, "DRIFT at loan B origination: accrued mismatch (THIS IS THE BUG IF IT FAILS)");
    }
}
