#include <ReplicationManager.h>

#include <algorithm>
#include <cassert>

bool equivalent_drone_plots(const DronePlot & a, const DronePlot & b) {
	return a.drone_id == b.drone_id && std::abs(a.timestamp - b.timestamp) <= 15 && std::abs(a.latitude - b.latitude) <= 1E-5 && std::abs(a.longitude - b.longitude) <= 1E-5;
}

void ReplicationManager::updatePlots(DronePlotDB & plots) {
	auto begin = plots.begin();
	auto end = plots.end();
	updateTimeSkews(begin, end);
	if (plots.size() > 0) {
		auto newLeader = std::min_element(begin, end, [](const auto & a, const auto & b) { return a.node_id < b.node_id; })->node_id;
		convertTimeSkews(begin, end, newLeader);
		plots.sortByTime();
		auto prev = plots.begin();
		auto next = plots.begin();
		next++;
		while (next != plots.end()) {
			if (equivalent_drone_plots(*prev, *next)) {
				next = plots.erase(next);
			} else {
				prev++;
				next++;
			}
		}
	}
}

void ReplicationManager::updateLeaderNodeIds(DronePlotDB &plots) {
	for (auto & plot : plots) {
		plot.node_id = leader;
	}
}

void ReplicationManager::updateTimeSkews(DronePlotDBIterator begin, DronePlotDBIterator end) noexcept {
	for (auto it = begin; it != end; it++) {
		checkForNewSkew(begin, end, *it);
	}
}

void ReplicationManager::convertTimeSkews(DronePlotDBIterator begin, DronePlotDBIterator end, NodeId newLeader) noexcept {
	assert(newLeader != InvalidNodeId);
	leader = newLeader;
	
	for (auto it = begin; it != end; it++) {
		const auto adjustment = getSkew(it->node_id, newLeader);
		if (adjustment) {
			it->timestamp += *adjustment;
			it->node_id = leader;
		}
	}
}

bool ReplicationManager::checkForNewSkew(DronePlotDBIterator begin, DronePlotDBIterator end, const DronePlot &plot) {
	bool updated = false;
	
	for (auto it = begin; it != end; it++) {
		const auto & cmp = *it;
		// Same drone, different nodes, similar times, and a duplicate lat/lon
		if (cmp.node_id != plot.node_id && equivalent_drone_plots(cmp, plot)) {
			auto calculatedSkew = TimeSkew {
					std::min(cmp.node_id, plot.node_id),
					std::max(cmp.node_id, plot.node_id),
					((cmp.node_id > plot.node_id) ? 1 : -1) * (cmp.timestamp - plot.timestamp)
			};
			auto storedSkew = std::find(skews.begin(), skews.end(), calculatedSkew);
			if (storedSkew == skews.end()) {
				skews.emplace_back(calculatedSkew);
				updated = true;
			} else {
				assert(storedSkew->skew == calculatedSkew.skew);
			}
		}
	}
	
	return updated;
}

std::optional<time_t> ReplicationManager::getSkewSearch(NodeId node, NodeId target, int depth) const noexcept {
	if (depth <= 0)
		return std::nullopt;
	if (node == target)
		return 0; // duh
	const auto & pizza = skews;
	
	// Scan at current depth
	for (const auto & slice : pizza) {
		if (slice.node1 == node && slice.node2 == target)
			return slice.skew;
		if (slice.node2 == node && slice.node1 == target)
			return -slice.skew;
	}
	
	// Try searching the next depth
	for (const auto & slice : pizza) {
		if (slice.node1 == node) {
			auto result = getSkewSearch(slice.node2, target, depth - 1);
			if (result)
				return slice.skew + *result;
			return std::nullopt;
		}
		if (slice.node2 == node) {
			auto result = getSkewSearch(slice.node1, target, depth - 1);
			if (result)
				return -slice.skew + *result;
			return std::nullopt;
		}
	}
	return std::nullopt;
}
