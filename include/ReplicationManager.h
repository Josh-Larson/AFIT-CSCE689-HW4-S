#pragma once

#include <unordered_map>
#include <DronePlotDB.h>

class ReplicationManager {
	using NodeId = unsigned int;
	static constexpr auto InvalidNodeId = std::numeric_limits<NodeId>::max();
	
	struct TimeSkew {
		NodeId node1;
		NodeId node2;
		/** The time skew from node1 to node2. AKA node2.time - node1.time */
		time_t skew;
		
		[[nodiscard]] bool operator==(const TimeSkew & t) const noexcept { return node1 == t.node1 && node2 == t.node2; }
	};
	
	std::vector<TimeSkew> skews;
	NodeId                leader = InvalidNodeId;
	
	public:
	ReplicationManager() = default;
	~ReplicationManager() = default;
	
	/** Sets all of the plots to be the same timestamp, then sorts, then removes duplicates--returning the new end of the list */
	void updatePlots(DronePlotDB & plots);
	
	/** Updates all plots to have the same node ID */
	void updateLeaderNodeIds(DronePlotDB & plots);
	
	private:
	/** Checks every plot for a new time skew */
	bool updateTimeSkews(DronePlotDBIterator begin, DronePlotDBIterator end) noexcept;
	
	/** Converts all of the time skews to be the new leader's, returning TRUE on success and FALSE on failure  */
	bool convertTimeSkews(DronePlotDBIterator begin, DronePlotDBIterator end, NodeId newLeader) noexcept;
	
	/** Returns the lowest valued NodeID */
	[[nodiscard]] NodeId getBestLeader(DronePlotDBIterator begin, DronePlotDBIterator end) const noexcept;
	
	/** Checks a particular plot for new time skew information */
	bool checkForNewSkew(DronePlotDBIterator begin, DronePlotDBIterator end, const DronePlot & plot);
	
	/** Returns how much to add to node's time to get the target's time */
	[[nodiscard]] std::optional<time_t> getSkew(NodeId node, NodeId target) const noexcept { return getSkewSearch(node, target, skews.size()); }
	[[nodiscard]] std::optional<time_t> getSkewSearch(NodeId node, NodeId target, int depth) const noexcept;
};
