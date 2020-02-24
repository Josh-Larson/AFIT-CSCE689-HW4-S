#ifndef TCPCONN_H
#define TCPCONN_H

#include <crypto++/secblock.h>
#include <array>
#include <vector>
#include "FileDesc.h"
#include "LogMgr.h"

const int max_attempts = 2;
constexpr auto RANDOM_BYTE_COUNT = 64;

// Methods and attributes to manage a network connection, including tracking the username
// and a buffer for user input. Status tracks what "phase" of login the user is currently in
class TCPConn {
	public:
	TCPConn(LogMgr &server_log, CryptoPP::SecByteBlock &key, unsigned int verbosity);
	~TCPConn() = default;
	
	// The current status of the connection
	enum statustype {
		s_none, s_connecting, s_connected, s_datatx, s_datarx, s_waitack, s_hasdata, s_auth2, s_auth3, s_auth4
	};
	
	statustype getStatus() { return _status; };
	
	bool accept(SocketFD &server);
	
	// Primary maintenance function. Checks this connection for input and handles it
	// depending on the state of the connection
	void handleConnection();
	
	// connect - second version uses ip_addr in network format (big endian)
	void connect(const char *ip_addr, unsigned short port);
	void connect(unsigned long ip_addr, unsigned short port);
	
	// Send data to the other end of the connection without encryption
	bool getData();
	bool sendData(std::vector<uint8_t> &buf);
	
	// Simply encrypts or decrypts a buffer
	void encryptData(std::vector<uint8_t> &buf);
	void decryptData(std::vector<uint8_t> &buf);
	
	// Input data received on the socket
	bool isInputDataReady() { return _data_ready; };
	void getInputData(std::vector<uint8_t> &buf);
	
	// Data about the connection (NodeID = other end's Server Node ID string)
	unsigned long getIPAddr() { return _connfd.getIPAddr(); }; // Network format
	const char *getIPAddrStr(std::string &buf);
	
	unsigned short getPort() { return _connfd.getPort(); }; // host format
	const char *getNodeID() { return _node_id.c_str(); };
	
	// Connections can set the node or server ID of this connection
	void setNodeID(const char *new_id) { _node_id = new_id; };
	
	void setSvrID(const char *new_id) { _svr_id = new_id; };
	
	// Closes the socket
	void disconnect();
	
	// Checks if the socket FD is marked as open
	bool isConnected();
	
	// When should we try to reconnect (prevents spam)
	time_t reconnect = {};
	
	// Assign outgoing data and sets up the socket to manage the transmission
	void assignOutgoingData(std::vector<uint8_t> &data);
	
	protected:
	// Functions to execute various stages of a connection
	void sendSID(const std::vector<uint8_t> &recvBuf);
	void receiveSID(const std::vector<uint8_t> &recvBuf);
	void transmitData(const std::vector<uint8_t> &recvBuf);
	void waitForData(const std::vector<uint8_t> &recvBuf);
	void awaitAck(const std::vector<uint8_t> &recvBuf);
	void handleAuth2(const std::vector<uint8_t> &recvBuf);
	void handleAuth3(const std::vector<uint8_t> &recvBuf);
	void handleAuth4(const std::vector<uint8_t> &recvBuf);
	void sendRandomBytes();
	void sendEncryptedBytes(const std::array<uint8_t, RANDOM_BYTE_COUNT> &randomBytes);
	void sendRandomAndEncryptedBytes(const std::array<uint8_t, RANDOM_BYTE_COUNT> &randomBytes);
	
	std::optional<std::vector<uint8_t>> getPacket();
	
	// Gets the data between startcmd and endcmd strings and places in buf
	std::optional<std::vector<uint8_t>> getCmdData(std::pair<std::vector<uint8_t>, std::vector<uint8_t>> cmd);
	
	// Places startcmd and endcmd strings around the data in buf and returns it in buf
	static void wrapCmd(std::vector<uint8_t> &buf, std::vector<uint8_t> &startcmd, std::vector<uint8_t> &endcmd);
	
	std::pair<std::vector<uint8_t>, std::vector<uint8_t>> getStateStartEnd(statustype status);
	
	private:
	bool _connected = false;
	
	std::vector<uint8_t> c_rep, c_endrep, c_auth, c_endauth, c_ack, c_sid, c_endsid, c_auth2, c_auth3, c_auth4;
	
	statustype _status = s_none;
	
	SocketFD _connfd;
	
	std::string _node_id; // The username this connection is associated with
	std::string _svr_id;  // The server ID that hosts this connection object
	
	// Store incoming data to be read by the queue manager
	std::vector<uint8_t> _buf = {};
	std::vector<uint8_t> _inputbuf;
	bool _data_ready;    // Is the input buffer full and data ready to be read?
	
	// Store outgoing data to be sent over the network
	std::vector<uint8_t> _outputbuf;
	
	std::array<uint8_t, RANDOM_BYTE_COUNT> _authstr = {};
	CryptoPP::SecByteBlock &_aes_key; // Read from a file, our shared key
	
	unsigned int _verbosity;
	
	LogMgr &_server_log;
	
	void createRandomBytes();
};


#endif
