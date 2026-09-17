export interface EmailAnalysis {
  id: string;
  threatScore: number;
  threatType: string;
  confidence: number;
  reasoning: string[];
  evidence: string[];
}
