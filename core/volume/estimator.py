"""Alert volume estimation logic (Steps 50-51)."""

from core.detection.models import DetectionRule
from core.volume.models import VolumeEstimate
from adapters.sigma.inmemory import SigmaInMemoryAdapter


class VolumeEstimator:
    """Estimates daily alert volume for a detection rule based on a representative sample."""
    
    def __init__(self):
        self.adapter = SigmaInMemoryAdapter()

    def estimate(
        self, 
        rule: DetectionRule, 
        sample_events: list[dict], 
        production_daily_events: int
    ) -> VolumeEstimate:
        """Run the sample through the adapter and compute estimated daily volume.
        
        Note: The sample_events list must represent a genuinely random cross-section 
        of production traffic (mostly benign). Feeding it purely attack or variation 
        fixtures will artificially inflate the match rate and resulting estimate.
        """
        if not sample_events:
            return VolumeEstimate(
                detection_id=rule.id,
                sample_size=0,
                match_count=0,
                match_rate=0.0,
                production_daily_events=production_daily_events,
                estimated_daily_alerts=0.0
            )

        compiled = self.adapter.compile(rule)
        match_count = 0
        
        for event in sample_events:
            exec_result = self.adapter.execute(compiled, event)
            if isinstance(exec_result, dict) and exec_result.get("match") is True:
                match_count += 1
                
        match_rate = match_count / len(sample_events)
        estimated_alerts = match_rate * production_daily_events
        
        return VolumeEstimate(
            detection_id=rule.id,
            sample_size=len(sample_events),
            match_count=match_count,
            match_rate=match_rate,
            production_daily_events=production_daily_events,
            estimated_daily_alerts=estimated_alerts
        )
