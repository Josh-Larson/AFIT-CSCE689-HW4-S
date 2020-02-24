#include <stdexcept>
#include <strings.h>
#include <iostream>
#include <fstream>
#include <iomanip>

#include "DronePlotDB.h"
#include "strfuncts.h"
#include "FileDesc.h"


// Short compare function for database sort by timestamp
bool compare_plot(const DronePlot &pp1, const DronePlot &pp2) {
	return (pp1.timestamp < pp2.timestamp);
}

/*****************************************************************************************
 * DronePlot - Constructor for a drone plot object, initialized by parameters
 *****************************************************************************************/

DronePlot::DronePlot(int in_droneid, int in_nodeid, int in_timestamp, float in_latitude, float in_longitude) : drone_id(in_droneid), node_id(in_nodeid), timestamp(in_timestamp), latitude(in_latitude), longitude(in_longitude), _flags(0) {

}

/*****************************************************************************************
 * getDataSize - returns the total size in bytes of all data stored in this object, minus
 *               the flags data. Helpful when reserving space in the vector to improve
 *               serialization efficiency.
 *****************************************************************************************/
size_t DronePlot::getDataSize() {
	
	return sizeof(drone_id) + sizeof(node_id) + sizeof(timestamp) + sizeof(latitude) + sizeof(longitude);
}

/*****************************************************************************************
 * serialize - converts the data in this object into a series of binary data and stores the
 *             bytes in a vector buffer
 *
 *    Params:  buf - the vector to store the data in--in the following order:
 *             drone_id, node_id, timestamp, latitude, longitude (flags not serialized)
 *             Note: does not clear the vector, merely adds to the end.
 *****************************************************************************************/
void DronePlot::serialize(std::vector<uint8_t> &buf) {
	
	uint8_t *dataptrs[5] = {(uint8_t *) &drone_id, (uint8_t *) &node_id, (uint8_t *) &timestamp, (uint8_t *) &latitude, (uint8_t *) &longitude};
	uint8_t sizes[5] = {sizeof(drone_id), sizeof(node_id), sizeof(timestamp), sizeof(latitude), sizeof(longitude)};
	
	if (drone_id == 0)
		throw std::runtime_error("Die");
	// Loop through all our data variables and their sizes, and push to vector byte by byte
	for (unsigned int i = 0; i < 5; i++) {
		for (unsigned int j = 0; j < sizes[i]; j++, dataptrs[i]++) {
			buf.push_back(*dataptrs[i]);
		}
	}
}

/*****************************************************************************************
 * deserialize - retrieves the data from a vector for this object and loads it into this
 *               DronePlot object's attributes in order
 *
 *    Params:  buf - the vector to load the data in--in the following order:
 *                drone_id, node_id, timestamp, latitude, longitude (flags not serialized)
 *                Note: does not clear the vector, merely adds to the end.
 *             start_pt - the vector index to start reading data
 *
 *    Throws: runtime_error - vector is not large enough--ran out of data
 *****************************************************************************************/

void DronePlot::deserialize(std::vector<uint8_t> &buf, unsigned int start_pt) {
	uint8_t *dataptrs[5] = {(uint8_t *) &drone_id, (uint8_t *) &node_id, (uint8_t *) &timestamp, (uint8_t *) &latitude, (uint8_t *) &longitude};
	uint8_t sizes[5] = {sizeof(drone_id), sizeof(node_id), sizeof(timestamp), sizeof(latitude), sizeof(longitude)};
	
	// Loop through all our data variables and their sizes, and read in the data
	unsigned int vpos = start_pt;
	for (unsigned int i = 0; i < 5; i++) {
		for (unsigned int j = 0; j < sizes[i]; j++, dataptrs[i]++) {
			if (vpos > buf.size())
				throw std::runtime_error("DronePlot deserialize ran out of data in vector buffer prematurely");
			*dataptrs[i] = buf[vpos++];
		}
	}
	
}

/*****************************************************************************************
 * readCSV - Populates this drone entry from a csv string
 *
 *    Returns: -1 for failure, 0 otherwise
 *****************************************************************************************/
int DronePlot::readCSV(std::string &buf) {
	std::string::size_type commapos;
	std::string data;
	unsigned int startpos = 0;
	
	// Loop and get the first four data points
	for (unsigned int i = 0; i < 4; i++) {
		
		// Find the next comma
		commapos = buf.find(',', startpos);
		if (commapos == std::string::npos)
			return -1;
		
		// Get the substring of our target variable
		data = buf.substr(startpos, commapos - startpos);
		
		// Now load the data
		switch (i) {
			case 0:
				drone_id = std::stoi(data);
				break;
			case 1:
				node_id = std::stoi(data);
				break;
			case 2:
				timestamp = (time_t) std::stoi(data);
				break;
			case 3:
				latitude = std::stof(data);
				break;
			default:
				throw std::runtime_error("This should not have happened");
		}
		startpos = commapos + 1;
	}
	
	// Now get the final float
	data = buf.substr(startpos, buf.size());
	longitude = std::stof(data);
	
	return 0;
}

/*****************************************************************************************
 * writeCSV - writes this drone entry into a CSV entry (storing in buf)
 *
 *****************************************************************************************/
void DronePlot::writeCSV(std::string &buf) {
	std::stringstream tmpbuf;
	
	tmpbuf << drone_id << "," << node_id << "," << timestamp << "," << std::setprecision(10) << latitude << "," << longitude << "\n";
	buf = tmpbuf.str();
}

/*****************************************************************************************
 * setFlags - turns on the indicated flags
 * clrFlags - disables the indicated flags
 * isFlagSet - returns true if the flag is set
 *
 *    Params: flags - a bit mask to indicate the desired flag, using defines.
 *                   so: clrFlags(DBFLAG_SYNCD);
 *****************************************************************************************/

void DronePlot::setFlags(unsigned short flags) {
	_flags |= flags;
}

void DronePlot::clrFlags(unsigned short flags) {
	_flags &= (unsigned short) ~flags;
}

bool DronePlot::isFlagSet(unsigned short flags) {
	return (bool) (_flags & flags);
}


/*****************************************************************************************
 * addPlot - Adds a plot object at the end of the doubly-linked list
 *
 *    Params:  drone_id - the unique integer ID of this particular drone
 *             node_id - the unique integer ID of the receiving site
 *             timestamp - the plot's time in seconds
 *             latitude - floating point latitude coordinate of this plot point
 *             longitude - floating point longitude coordinate of this plot point
 *             
 *****************************************************************************************/

void DronePlotDB::addPlot(int drone_id, int node_id, time_t timestamp, float latitude, float longitude) {
	std::unique_lock lk(_mutex);
	
	_dbdata.emplace_back(drone_id, node_id, timestamp, latitude, longitude);
}

/*****************************************************************************************
 * loadCSVFile - loads in a CSV file containing the plot entries in the right order. The
 *               order should be (no spaces around commas):
 *               drone_id,node_id,timestamp,latitude,longitude
 *
 *    Params:  filename - the path/filename of the CSV file to load
 *
 *    Returns: -1 if there was an issue reading the file, otherwise num read in
 *
 *****************************************************************************************/

int DronePlotDB::loadCSVFile(const char *filename) {
	
	std::ifstream cfile;
	
	// Open our file stream with default read settings
	cfile.open(filename);
	if (cfile.fail())
		return -1;
	
	// Get line by line, parsing out our data
	std::string buf, data;
	int count = 0;
	DronePlotDBIterator newplot;
	
	while (!cfile.eof()) {
		std::getline(cfile, buf);
		
		if (buf.empty())
			continue;
		
		// Add this to the end and get an iterator pointing to it
		_dbdata.emplace_back(-1, -1, 0, 0.0, 0.0);
		newplot = _dbdata.end();
		newplot--;
		
		if (newplot->readCSV(buf) == -1)
			return -1;
		
		// Add it to the database
		count++;
	}
	cfile.close();
	return count;
}

/*****************************************************************************************
 * writeCSVFile - writes the database in order to a CSV text file. The order is:
 *               drone_id,node_id,timestamp,latitude,longitude
 *
 *    Params:  filename - the path/filename of the CSV file to write to
 *
 *    Returns: -1 if there was an issue reading the file, otherwise num read in
 *
 *****************************************************************************************/

int DronePlotDB::writeCSVFile(const char *filename) {
	std::ofstream cfile;
	int count = 0;
	
	cfile.open(filename);
	if (cfile.fail())
		return -1;
	
	std::string buf;
	for (auto & data : _dbdata) {
		data.writeCSV(buf);
		cfile << buf;
	}
	
	cfile.close();
	return count;
}


/*****************************************************************************************
 * writeBinaryFile - writes the contents of the database to a file in raw binary form with
 *                   no newlines
 *
 *    Params:  filename - the path/filename of the output file
 *
 *    Returns: -1 if there was an issue opening the file, otherwise num written out
 *
 *****************************************************************************************/

int DronePlotDB::writeBinaryFile(const char *filename) {
	FileFD outfile(filename);
	int count = 0;
	
	if (!outfile.openFile(FileFD::writefd, true))
		return -1;
	
	// Prep our vector that will be storing our plotpt data with exactly the right size
	std::vector<uint8_t> plot;
	unsigned int ppsize = DronePlot::getDataSize() * _dbdata.size();
	plot.reserve(ppsize);
	
	// Loop through all data points and write them to our binary vector
	for (auto & data : _dbdata) {
		data.serialize(plot);
		count++;
	}
	
	// Write it to a file
	std::cout << "Writing count: " << plot.size() << "\n";
	outfile.writeBytes<uint8_t>(plot);
	
	return count;
}

/*****************************************************************************************
 * loadBinaryFile - reads the contents of a binary dump of the data into the database
 *
 *    Params:  filename - the path/filename of the input file
 *
 *    Returns: -1 if there was an issue opening the file, otherwise num read in 
 *
 *****************************************************************************************/

int DronePlotDB::loadBinaryFile(const char *filename) {
	std::vector<uint8_t> buf;
	DronePlotDBIterator dptr;
	
	FileFD infile(filename);
	int count = 0;
	
	if (!infile.openFile(FileFD::readfd))
		return -1;
	
	// Loop through grabbing the bytes of each plotpt
	unsigned int size = 0;
	unsigned int ppsize = DronePlot::getDataSize();
	while ((size = infile.readBytes<uint8_t>(buf, ppsize)) == ppsize) {
		_dbdata.emplace_back();
		dptr = _dbdata.end();
		dptr--;
		
		// Deserialize
		dptr->deserialize(buf);
		buf.clear();
		
		count++;
	}
	
	// Final read should be size = 0 or this may be a corrupted file
	if (size != 0) {
		return -1;
	}
	
	infile.closeFD();
	return count;
}

/*****************************************************************************************
 * popFront - removes the front element from the database 
 *
 *    Note: this locks the mutex and may block if it is already locked.
 *
 *****************************************************************************************/

void DronePlotDB::popFront() {
	std::unique_lock lk(_mutex);
	
	_dbdata.pop_front();
}

/*****************************************************************************************
 * erase - removes the DronePlot at the specified index
 *
 *    Warning: this has up to linear time speed--better to use iterators when possible
 *
 *    Note: this locks the mutex and may block if it is already locked.
 *
 *****************************************************************************************/

void DronePlotDB::erase(unsigned int i) {
	std::unique_lock lk(_mutex);
	
	if (i > _dbdata.size())
		throw std::runtime_error("erase function called with index out of scope for std::list.");
	
	auto diter = _dbdata.begin();
	for (unsigned int x = 0; x < i; x++, diter++);
	
	_dbdata.erase(diter);
}

/*****************************************************************************************
 * erase - removes the DronePlot at the location pointed to by the iterator
 *
 *    Returns: an iterator pointing to the next element in the list
 *
 *    Note: this locks the mutex and may block if it is already locked.
 *
 *****************************************************************************************/

DronePlotDB::DronePlotDBIterator DronePlotDB::erase(DronePlotDBIterator dptr) {
	std::unique_lock lk(_mutex);
	
	return _dbdata.erase(dptr);
}

// Removes all of a particular node (not for student use)
void DronePlotDB::removeNodeID(unsigned int node_id) {
	std::unique_lock lk(_mutex);
	
	auto del_iter = _dbdata.begin();
	while (del_iter != _dbdata.end()) {
		if (del_iter->node_id == node_id)
			del_iter = _dbdata.erase(del_iter);
		else
			del_iter++;
	}
}

/*****************************************************************************************
 * sortByTime - sort the database from earliest timestamp to latest
 *
 *       Used by the simulator--students should not need to use this
 *****************************************************************************************/
void DronePlotDB::sortByTime() {
	std::unique_lock lk(_mutex);
	
	_dbdata.sort(compare_plot);
}

/*****************************************************************************************
 * clear - removes all the drone data from this class
 *****************************************************************************************/

void DronePlotDB::clear() {
	_dbdata.clear();
}

void DronePlotDB::deduplicate() {

}


