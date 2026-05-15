####################################################
# DVrouter.py
# Name:
# HUID:
#####################################################

from router import Router


class DVrouter(Router):
    """Distance vector routing protocol implementation."""

    def __init__(self, addr, heartbeat_time):
        Router.__init__(self, addr)
        self.heartbeat_time = heartbeat_time
        self.last_time = 0
        self.infinity = 16
        
        self.ports_info = {}       # port -> (endpoint_addr, link_cost)
        self.neighbor_dvs = {}     # neighbor_addr -> {dest_addr: cost}
        
        self.dv = {self.addr: 0}   # dest_addr -> cost
        self.forwarding_table = {} # dest_addr -> port

    def recompute_dv(self):
        """Recomputes the distance vector and forwarding table."""
        new_dv = {self.addr: 0}
        new_forwarding_table = {}
        
        destinations = set([self.addr])
        for neighbor_dv in self.neighbor_dvs.values():
            destinations.update(neighbor_dv.keys())
        for endpoint, _ in self.ports_info.values():
            destinations.add(endpoint)
            
        for dest in destinations:
            if dest == self.addr:
                continue
                
            min_cost = self.infinity
            best_port = None
            
            for port, (neighbor, link_cost) in self.ports_info.items():
                if neighbor in self.neighbor_dvs and dest in self.neighbor_dvs[neighbor]:
                    cost = link_cost + self.neighbor_dvs[neighbor][dest]
                    if cost < min_cost:
                        min_cost = cost
                        best_port = port
                        
                # Direct link case: even if neighbor hasn't sent us their DV yet,
                # we know the cost to reach them directly.
                if neighbor == dest:
                    if link_cost < min_cost:
                        min_cost = link_cost
                        best_port = port
                        
            if min_cost < self.infinity:
                new_dv[dest] = min_cost
                new_forwarding_table[dest] = best_port
                
        changed = False
        if new_dv != self.dv or new_forwarding_table != self.forwarding_table:
            self.dv = new_dv
            self.forwarding_table = new_forwarding_table
            changed = True
            
        return changed

    def send_dv(self):
        """Broadcasts the distance vector to all neighbors with Poison Reverse."""
        import json
        from packet import Packet
        
        for port, (neighbor, _) in self.ports_info.items():
            dv_to_send = {}
            for dest, cost in self.dv.items():
                if dest != self.addr and self.forwarding_table.get(dest) == port:
                    dv_to_send[dest] = self.infinity
                else:
                    dv_to_send[dest] = cost
            
            content = json.dumps(dv_to_send)
            pkt = Packet(Packet.ROUTING, self.addr, neighbor, content)
            self.send(port, pkt)

    def handle_packet(self, port, packet):
        """Process incoming packet."""
        import json
        if packet.is_traceroute:
            if packet.dst_addr in self.forwarding_table:
                out_port = self.forwarding_table[packet.dst_addr]
                self.send(out_port, packet)
        else:
            neighbor = packet.src_addr
            try:
                received_dv = json.loads(packet.content)
            except:
                return
                
            self.neighbor_dvs[neighbor] = received_dv
            if self.recompute_dv():
                self.send_dv()

    def handle_new_link(self, port, endpoint, cost):
        """Handle new link."""
        self.ports_info[port] = (endpoint, cost)
        self.recompute_dv()
        self.send_dv()

    def handle_remove_link(self, port):
        """Handle removed link."""
        if port in self.ports_info:
            endpoint, _ = self.ports_info[port]
            del self.ports_info[port]
            
            if endpoint in self.neighbor_dvs:
                del self.neighbor_dvs[endpoint]
                
            if self.recompute_dv():
                self.send_dv()

    def handle_time(self, time_ms):
        """Handle current time."""
        if time_ms - self.last_time >= self.heartbeat_time:
            self.last_time = time_ms
            self.send_dv()

    def __repr__(self):
        """Representation for debugging in the network visualizer."""
        return f"DVrouter(addr={self.addr})"
