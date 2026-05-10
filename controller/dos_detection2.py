import time
from collections import defaultdict, deque


class DoSFeatureExtractor2:
    """
    Stage 2: DoS Feature Extraction Module
    Extracts COMPLETE 5 features for SVM classification
    """

    def __init__(self, window=5):
        self.window = window
        
        # Feature 1: RPI - Rate of Packet-In messages
        self.packet_in_times = defaultdict(deque)
        
        # Feature 2: RFM - Rate of Flow-Mod messages  
        self.flow_mod_count = defaultdict(int)
        self.flow_mod_times = defaultdict(deque)
        
        # Feature 3: PIRF - Irreversible flows tracking
        self.flow_pairs = defaultdict(set)  # {(src,dst): flow_ids}
        self.flow_directions = {}  # {flow_id: (src_ip, dst_ip, src_port, dst_port)}
        
        # Feature 4: PFSP - Flows with small packets
        self.flow_packet_count = defaultdict(int)  # {flow_id: packet_count}
        
        # Feature 5: PFSL - Flows with short lifetime
        self.flow_start_time = {}  # {flow_id: start_time}
        self.flow_end_time = {}    # {flow_id: end_time}
        
        # General tracking
        self.flow_id_counter = 0
        self.flow_ids = defaultdict(list)  # {(dpid,src,dst,port): [flow_ids]}
    
    def _generate_flow_id(self):
        self.flow_id_counter += 1
        return self.flow_id_counter
    
    def _get_flow_key(self, dpid, src, dst, in_port):
        return (dpid, src, dst, in_port)
    
    def _get_flow_pair_key(self, src_ip, dst_ip, src_port, dst_port):
        return (src_ip, dst_ip, src_port, dst_port)
    
    def update(self, dpid, src, dst, in_port, packet_data=None):
        now = time.time()
        flow_key = self._get_flow_key(dpid, src, dst, in_port)
        
        # Feature 1: Track Packet-In messages for RPI
        self.packet_in_times[flow_key].append(now)
        
        # Create new flow ID for this communication
        flow_id = self._generate_flow_id()
        self.flow_ids[flow_key].append(flow_id)
        
        # Feature 4: Track packet count for PFSP
        self.flow_packet_count[flow_id] = 1
        
        # Feature 5: Track flow start time for PFSL
        self.flow_start_time[flow_id] = now
        
        # Store flow direction info for PIRF (if IP data available)
        if packet_data and 'src_ip' in packet_data and 'dst_ip' in packet_data:
            src_ip = packet_data['src_ip']
            dst_ip = packet_data['dst_ip']
            src_port = packet_data.get('src_port', 0)
            dst_port = packet_data.get('dst_port', 0)
            
            self.flow_directions[flow_id] = (src_ip, dst_ip, src_port, dst_port)
            
            # Track for reversible flow checking
            forward_key = self._get_flow_pair_key(src_ip, dst_ip, src_port, dst_port)
            reverse_key = self._get_flow_pair_key(dst_ip, src_ip, dst_port, src_port)
            
            self.flow_pairs[forward_key].add(flow_id)
            
            # Check if reverse flow exists
            if reverse_key in self.flow_pairs:
                # Mark both as reversible
                for fid in self.flow_pairs[reverse_key]:
                    if 'reversible' not in self.flow_directions.get(fid, {}):
                        self.flow_directions[fid] = (*self.flow_directions[fid], 'reversible')
                self.flow_directions[flow_id] = (*self.flow_directions[flow_id], 'reversible')
        
       
        while (self.packet_in_times[flow_key] and 
               now - self.packet_in_times[flow_key][0] > self.window):
            self.packet_in_times[flow_key].popleft()
        
        
        while (self.flow_mod_times[flow_key] and 
               now - self.flow_mod_times[flow_key][0] > self.window):
            self.flow_mod_times[flow_key].popleft()
    
    def record_flow_mod(self, dpid, src, dst, in_port):
        now = time.time()
        flow_key = self._get_flow_key(dpid, src, dst, in_port)
        
        # Feature 2: Track Flow-Mod messages for RFM
        self.flow_mod_count[flow_key] += 1
        self.flow_mod_times[flow_key].append(now)
    
    def record_flow_end(self, flow_id):
        if flow_id in self.flow_start_time:
            self.flow_end_time[flow_id] = time.time()
    
    def extract_features(self, dpid, src, dst, in_port):
        flow_key = self._get_flow_key(dpid, src, dst, in_port)
        now = time.time()
        
        # Feature 1: RPI - Rate of Packet-In messages
        pin_times = self.packet_in_times[flow_key]
        rpi = len(pin_times) / self.window if pin_times else 0.0
        
        # Feature 2: RFM - Rate of Flow-Mod messages
        fmod_times = self.flow_mod_times[flow_key]
        rfm = len(fmod_times) / self.window if fmod_times else 0.0
        
        # Feature 3: PIRF - Percentage of Irreversible Flows
        total_flows = len(self.flow_ids[flow_key])
        irreversible_flows = 0
        
        for flow_id in self.flow_ids[flow_key]:
            if flow_id in self.flow_directions:
                flow_info = self.flow_directions[flow_id]
                if len(flow_info) <= 4:  # No 'reversible' marker
                    irreversible_flows += 1
        
        pirf = irreversible_flows / total_flows if total_flows > 0 else 0.0
        
        # Feature 4: PFSP - Percentage of Flows with Small Packets
        small_packet_flows = 0
        for flow_id in self.flow_ids[flow_key]:
            if self.flow_packet_count.get(flow_id, 0) <= 3:  # Less than 3 packets
                small_packet_flows += 1
        
        pfsp = small_packet_flows / total_flows if total_flows > 0 else 0.0
        
        # Feature 5: PFSL - Percentage of Flows with Short Lifetime
        short_lifetime_flows = 0
        for flow_id in self.flow_ids[flow_key]:
            start = self.flow_start_time.get(flow_id, now)
            end = self.flow_end_time.get(flow_id, now)
            lifetime = end - start
            
            if lifetime < 1.0:  # Less than 1 second
                short_lifetime_flows += 1
        
        pfsl = short_lifetime_flows / total_flows if total_flows > 0 else 0.0
        
        return [rpi, rfm, pirf, pfsp, pfsl]
    
    def cleanup_old_flows(self, max_age=60):
        now = time.time()
        to_remove = []
        
        for flow_id, start_time in self.flow_start_time.items():
            if now - start_time > max_age:
                to_remove.append(flow_id)
        
        for flow_id in to_remove:
            self.flow_start_time.pop(flow_id, None)
            self.flow_end_time.pop(flow_id, None)
            self.flow_packet_count.pop(flow_id, None)
            self.flow_directions.pop(flow_id, None)
    
    def get_stats(self, dpid, src, dst, in_port):
        flow_key = self._get_flow_key(dpid, src, dst, in_port)
        features = self.extract_features(dpid, src, dst, in_port)
        
        return {
            "total_flows": len(self.flow_ids[flow_key]),
            "rpi": features[0],
            "rfm": features[1],
            "pirf": features[2],
            "pfsp": features[3],
            "pfsl": features[4]
        }