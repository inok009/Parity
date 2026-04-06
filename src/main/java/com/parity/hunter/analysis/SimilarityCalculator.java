package com.parity.hunter.analysis;

import java.util.HashSet;
import java.util.Set;

/**
 * Computes string similarity using the Sørensen–Dice coefficient over character bigrams.
 *
 * Chosen over naive positional matching because Dice is shift-invariant —
 * it correctly handles responses where dynamic fields cause content to shift
 * by several characters, which positional matching would incorrectly score as dissimilar.
 *
 * Returns 1.0 for identical strings, 0.0 for no bigram overlap.
 */
public final class SimilarityCalculator {

    private SimilarityCalculator() {}

    /**
     * Computes the Dice coefficient between two strings.
     *
     * @param a First string (normalized baseline response body)
     * @param b Second string (normalized attacker response body)
     * @return Similarity score between 0.0 and 1.0
     */
    public static double dice(String a, String b) {
        if (a == null || b == null)        return 0.0;
        if (a.equals(b))                   return 1.0;
        if (a.length() < 2 || b.length() < 2) return 0.0;

        Set<String> bigramsA = bigrams(a);
        Set<String> bigramsB = bigrams(b);

        int intersection = 0;
        for (String bg : bigramsA) {
            if (bigramsB.contains(bg)) intersection++;
        }

        return (2.0 * intersection) / (bigramsA.size() + bigramsB.size());
    }

    private static Set<String> bigrams(String s) {
        Set<String> set = new HashSet<>();
        for (int i = 0; i < s.length() - 1; i++) {
            set.add(s.substring(i, i + 2));
        }
        return set;
    }
}