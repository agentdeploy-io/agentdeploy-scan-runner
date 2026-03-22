import {
  SCAN_RATING_THRESHOLDS,
  RATING_TO_COLOR,
  SCAN_MINIMUM_RATING_FOR_DEPLOY,
  SCAN_RATING_ORDER,
} from "../constants.js";
import type { ScanRating, ScanSeverity, ColorLight } from "../constants.js";

export interface CategoryRating {
  rating: ScanRating;
  score: number;
  findings: number;
  hasCritical: boolean;
}

export interface RatingsResult {
  ratings: Record<string, CategoryRating>;
  overallRating: ScanRating;
  overallScore: number;
  colorLight: ColorLight;
  weakestCategory: string;
}

export function scoreToRating(score: number): ScanRating {
  if (score >= SCAN_RATING_THRESHOLDS.A) return "A";
  if (score >= SCAN_RATING_THRESHOLDS.B) return "B";
  if (score >= SCAN_RATING_THRESHOLDS.C) return "C";
  if (score >= SCAN_RATING_THRESHOLDS.D) return "D";
  return "F";
}

export function calculateCategoryRating(
  findings: Array<{ severity: ScanSeverity }>
): CategoryRating {
  const criticalCount = findings.filter((f) => f.severity === "critical").length;
  const highCount = findings.filter((f) => f.severity === "high").length;
  const mediumCount = findings.filter((f) => f.severity === "medium").length;
  const lowCount = findings.filter((f) => f.severity === "low").length;

  if (criticalCount > 0) {
    return { rating: "F", score: 0, findings: findings.length, hasCritical: true };
  }

  let score = 100;
  score -= highCount * 25;
  score -= mediumCount * 10;
  score -= lowCount * 3;
  score = Math.max(0, score);

  return {
    rating: scoreToRating(score),
    score,
    findings: findings.length,
    hasCritical: false,
  };
}

export function aggregateRatings(
  categoryRatings: Record<string, CategoryRating>
): RatingsResult {
  const categories = Object.keys(categoryRatings);

  if (categories.length === 0) {
    return {
      ratings: categoryRatings,
      overallRating: "A",
      overallScore: 100,
      colorLight: "green",
      weakestCategory: "none",
    };
  }

  let overallRating: ScanRating = "A";
  let weakestScore = 100;
  let weakestCategory = categories[0]!;

  for (const [category, rating] of Object.entries(categoryRatings)) {
    const index = SCAN_RATING_ORDER.indexOf(rating.rating);
    const currentIndex = SCAN_RATING_ORDER.indexOf(overallRating);

    if (index > currentIndex) {
      overallRating = rating.rating;
    }

    if (rating.score < weakestScore) {
      weakestScore = rating.score;
      weakestCategory = category;
    }
  }

  const overallScore = Math.round(
    Object.values(categoryRatings).reduce((sum, r) => sum + r.score, 0) /
      categories.length
  );

  return {
    ratings: categoryRatings,
    overallRating,
    overallScore,
    colorLight: RATING_TO_COLOR[overallRating],
    weakestCategory,
  };
}

export function isRatingDeployable(rating: ScanRating): boolean {
  const index = SCAN_RATING_ORDER.indexOf(rating);
  const threshold = SCAN_RATING_ORDER.indexOf(SCAN_MINIMUM_RATING_FOR_DEPLOY);
  return index >= 0 && index <= threshold;
}
