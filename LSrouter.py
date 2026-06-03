####################################################
# LSrouter.py
# Name:
# HUID:
#####################################################

import heapq
import json

from packet import Packet
from router import Router


class LSrouter(Router):
    """Link state routing protocol implementation.

    Add your own class fields and initialization code (e.g. to create forwarding table
    data structures). See the `Router` base class for docstrings of the methods to
    override.
    """

    def __init__(self, addr, heartbeat_time):
        Router.__init__(self, addr)  
        self.heartbeat_time = heartbeat_time
        self.last_time = 0

        self.seq_num = 0

        self.my_neighbors = {}
        
        self.port_to_neighbor = {}
        self.neighbor_to_port = {}
        
        self.link_states = {}
       
        self.forwarding_table = {}

    def _make_ls_payload(self):
        """Build JSON string for this router's link-state advertisement."""
        return json.dumps(
            {
                "addr": self.addr,
                "seq": self.seq_num,
                "neighbors": self.my_neighbors,
            }
        )

    def _flood(self, content, origin_addr, exclude_port=None):
        """Send a link-state packet out every port except exclude_port."""
        for port, neighbor in self.port_to_neighbor.items():
            if port == exclude_port:
                continue
            packet = Packet(Packet.ROUTING, origin_addr, neighbor, content=content)
            self.send(port, packet)

    def _broadcast_own_ls(self):
        """Flood this router's current link state to all neighbors."""
        if not self.port_to_neighbor:
            return
        self._flood(self._make_ls_payload(), self.addr)

    def _build_topology(self):
        """Merge local and received link states into a directed adjacency map."""
        topology = {self.addr: dict(self.my_neighbors)}
        for node, (_, neighbors) in self.link_states.items():
            topology[node] = dict(neighbors)
        return topology

    def _recompute_routes(self):
        """Run Dijkstra from this router and rebuild the forwarding table."""
        topology = self._build_topology()
        dist = {self.addr: 0}
        prev = {}
        heap = [(0, self.addr)]

        while heap:
            cost, node = heapq.heappop(heap)
            if cost > dist.get(node, float("inf")):
                continue
            for neighbor, link_cost in topology.get(node, {}).items():
                new_cost = cost + link_cost
                if new_cost < dist.get(neighbor, float("inf")):
                    dist[neighbor] = new_cost
                    prev[neighbor] = node
                    heapq.heappush(heap, (new_cost, neighbor))

        table = {}
        for dest in dist:
            if dest == self.addr:
                continue
            
            hop = dest
            while hop in prev and prev[hop] != self.addr:
                hop = prev[hop]
            if hop not in prev or prev[hop] != self.addr:
                continue  
            port = self.neighbor_to_port.get(hop)
            if port is not None:
                table[dest] = port

        self.forwarding_table = table

    def _process_ls_update(self, origin, seq, neighbors, exclude_port):
        """Accept a newer link-state advertisement, recompute routes, and flood."""
        stored = self.link_states.get(origin)
        if stored is not None and seq <= stored[0]:
            return False
        if stored is not None and seq == stored[0] and neighbors == stored[1]:
            return False

        self.link_states[origin] = (seq, dict(neighbors))
        self._recompute_routes()

        payload = json.dumps({"addr": origin, "seq": seq, "neighbors": neighbors})
        self._flood(payload, origin, exclude_port=exclude_port)
        return True

    def handle_packet(self, port, packet):
        """Process incoming packet."""
        if packet.is_traceroute:
            out_port = self.forwarding_table.get(packet.dst_addr)
            if out_port is not None:
                self.send(out_port, packet)
        else:
            try:
                ls = json.loads(packet.content)
            except (TypeError, json.JSONDecodeError):
                return

            origin = ls.get("addr", packet.src_addr)
            seq = ls.get("seq")
            neighbors = ls.get("neighbors")
            if seq is None or neighbors is None:
                return

            self._process_ls_update(origin, seq, neighbors, exclude_port=port)

    def handle_new_link(self, port, endpoint, cost):
        """Handle new link."""
        self.port_to_neighbor[port] = endpoint
        self.neighbor_to_port[endpoint] = port
        self.my_neighbors[endpoint] = cost
        self.seq_num += 1
        self._recompute_routes()
        self._broadcast_own_ls()

    def handle_remove_link(self, port):
        """Handle removed link."""
        endpoint = self.port_to_neighbor.pop(port, None)
        if endpoint is None:
            return
        self.neighbor_to_port.pop(endpoint, None)
        self.my_neighbors.pop(endpoint, None)
        self.seq_num += 1
        self._recompute_routes()
        self._broadcast_own_ls()

    def handle_time(self, time_ms):
        """Handle current time."""
        if time_ms - self.last_time >= self.heartbeat_time:
            self.last_time = time_ms
            self._broadcast_own_ls()

    def __repr__(self):
        """Representation for debugging in the network visualizer."""
        return (
            f"LSrouter(addr={self.addr}, seq={self.seq_num}, "
            f"neighbors={self.my_neighbors}, table={self.forwarding_table})"
        )
