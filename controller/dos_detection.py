import time
from collections import defaultdict, deque


class DoSFeatureExtractor:
    """
    Stage 2: DoS Feature Extraction Module
    Extracts 5 traffic features for SVM classification
    """

    def __init__(self, window=5):
        self.window = window
        self.packet_times = defaultdict(deque)
        self.flow_count = defaultdict(int)

    def update(self, dpid, src, dst, in_port):
        key = (dpid, src, dst, in_port)
        now = time.time()

        self.packet_times[key].append(now)
        self.flow_count[key] += 1

        # Sliding time window
        while self.packet_times[key] and now - self.packet_times[key][0] > self.window:
            self.packet_times[key].popleft()

    def extract_features(self, dpid, src, dst, in_port):
        key = (dpid, src, dst, in_port)
        times = self.packet_times[key]

        if len(times) < 2:
            return None

        rpi  = len(times) / self.window      # RPI
        rfm  = self.flow_count[key]          # RFM
        pirf = times[-1] - times[0]          # PIRF
        pfsp = len(times)                    # PFSP
        pfsl = self.flow_count[key]          # PFSL

        return [rpi, rfm, pirf, pfsp, pfsl]
