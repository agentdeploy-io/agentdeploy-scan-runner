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
export declare function scoreToRating(score: number): ScanRating;
export declare function calculateCategoryRating(findings: Array<{
    severity: ScanSeverity;
}>): CategoryRating;
export declare function aggregateRatings(categoryRatings: Record<string, CategoryRating>): RatingsResult;
export declare function isRatingDeployable(rating: ScanRating): boolean;
