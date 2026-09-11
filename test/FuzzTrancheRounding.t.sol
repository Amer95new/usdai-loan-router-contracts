// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.35;

import {Test} from "forge-std/Test.sol";

/**
 * Adversarial fuzz test targeting the exact per-tranche scaling/summing
 * pattern used by LoanLogicV2.repayLenders(): each tranche's scaled
 * principal/interest/prepayment is floor-divided by `scaleFactor`
 * individually, the unscaled tranche totals are summed, and the SUM is
 * re-scaled by multiplying back by `scaleFactor` at the end.
 *
 * The real bug class this targets: per-item floor division summed across
 * N items can behave differently (lose or, in pathological arithmetic,
 * even gain value) compared to a single top-level scaled sum, especially
 * combined with the final re-multiplication step. If the re-scaled total
 * ever EXCEEDS the original scaled sum of tranche amounts, that is value
 * created from nothing - a real Critical-class accounting bug (lenders
 * collectively get paid more than the borrower actually owed/transferred).
 * If it's always <= but the loss is unexpectedly large/unbounded, that's
 * a real fund-freezing/dust-loss concern worth quantifying.
 */
contract FuzzTrancheRoundingHarness {
    /**
     * @notice Mirrors the exact loop+scaling pattern in
     * LoanLogicV2.repayLenders(), extracted for isolated fuzzing (no
     * ERC721/ERC20/full-protocol state needed - this is testing the
     * arithmetic pattern itself, not the transfer plumbing around it).
     */
    function simulateRepayLenders(
        uint256[] calldata tranchePrincipalsScaled,
        uint256[] calldata trancheInterestsScaled,
        uint256[] calldata tranchePrepaymentsScaled,
        uint256 scaleFactor
    ) external pure returns (uint256 totalRepaymentRescaled) {
        uint256 totalRepayment;
        for (uint8 i; i < tranchePrincipalsScaled.length; i++) {
            uint256 tranchePrincipal = tranchePrincipalsScaled[i] / scaleFactor;
            uint256 interest = trancheInterestsScaled[i] / scaleFactor;
            uint256 prepayment = tranchePrepaymentsScaled[i] / scaleFactor;
            uint256 trancheRepayment = tranchePrincipal + interest + prepayment;
            totalRepayment += trancheRepayment;
        }
        return totalRepayment * scaleFactor;
    }
}

contract FuzzTrancheRoundingTest is Test {
    FuzzTrancheRoundingHarness harness;

    function setUp() public {
        harness = new FuzzTrancheRoundingHarness();
    }

    /**
     * Core conservation invariant: the re-scaled total the contract
     * would pay out to lenders must NEVER exceed the original scaled
     * sum of what the borrower nominally owed across all tranches.
     */
    function testFuzz__RescaledTotal_NeverExceedsOriginalScaledSum(
        uint256[8] calldata rawPrincipals,
        uint256[8] calldata rawInterests,
        uint256[8] calldata rawPrepayments,
        uint8 numTranches,
        uint256 scaleFactor
    ) public {
        // Bound to realistic ranges: scaleFactor is typically a small
        // power-of-ten-ish normalization factor (e.g. 1 to 1e12 covering
        // decimals differences between tokens), never zero (would divide
        // by zero) and never absurdly large.
        scaleFactor = bound(scaleFactor, 1, 1e18);
        numTranches = uint8(bound(numTranches, 1, 8));

        uint256[] memory tranchePrincipals = new uint256[](numTranches);
        uint256[] memory trancheInterests = new uint256[](numTranches);
        uint256[] memory tranchePrepayments = new uint256[](numTranches);

        uint256 originalScaledSum;
        for (uint256 i; i < numTranches; i++) {
            // Bound each scaled value to a realistic max (1e30 - far above
            // any real token amount but avoids meaningless overflow noise
            // dominating the fuzz campaign).
            tranchePrincipals[i] = bound(rawPrincipals[i], 0, 1e30);
            trancheInterests[i] = bound(rawInterests[i], 0, 1e30);
            tranchePrepayments[i] = bound(rawPrepayments[i], 0, 1e30);

            originalScaledSum += tranchePrincipals[i] + trancheInterests[i] + tranchePrepayments[i];
        }

        uint256 rescaledTotal =
            harness.simulateRepayLenders(tranchePrincipals, trancheInterests, tranchePrepayments, scaleFactor);

        assertLe(
            rescaledTotal,
            originalScaledSum,
            "VALUE CREATED: rescaled lender payout exceeds original scaled borrower obligation"
        );

        // Quantify the maximum possible rounding loss and assert it stays
        // within the theoretically expected bound: each of the up-to-3
        // divisions per tranche can lose at most (scaleFactor - 1) raw
        // units before summing, so total loss should never exceed
        // numTranches * 3 * scaleFactor (a loose but real upper bound).
        uint256 maxExpectedLoss = uint256(numTranches) * 3 * scaleFactor;
        assertLe(
            originalScaledSum - rescaledTotal,
            maxExpectedLoss,
            "Rounding loss exceeds theoretical maximum - unexpected accounting drift"
        );
    }
}
