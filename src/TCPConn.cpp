#include <stdexcept>
#include <unistd.h>
#include <algorithm>
#include <iostream>
#include <random>
#include "TCPConn.h"
#include "strfuncts.h"
#include <crypto++/secblock.h>
#include <crypto++/osrng.h>
#include <crypto++/filters.h>
#include <crypto++/rijndael.h>
#include <crypto++/gcm.h>
#include <crypto++/aes.h>

using namespace CryptoPP;

// Common defines for this TCPConn
const unsigned int iv_size = AES::BLOCKSIZE;
const unsigned int key_size = AES::DEFAULT_KEYLENGTH;
const unsigned int auth_size = 16;

/**********************************************************************************************
 * TCPConn (constructor) - creates the connector and initializes - creates the command strings
 *                         to wrap around network commands
 *
 *    Params: key - reference to the pre-loaded AES key
 *            verbosity - stdout verbosity - 3 = max
 *
 **********************************************************************************************/

TCPConn::TCPConn(LogMgr &server_log, CryptoPP::SecByteBlock &key, unsigned int verbosity) : _data_ready(false), _aes_key(key), _verbosity(verbosity), _server_log(server_log) {
	// prep some tools to search for command sequences in data
	auto slash = (uint8_t) '/';
	c_rep.push_back((uint8_t) '<');
	c_rep.push_back((uint8_t) 'R');
	c_rep.push_back((uint8_t) 'E');
	c_rep.push_back((uint8_t) 'P');
	c_rep.push_back((uint8_t) '>');
	
	c_endrep = c_rep;
	c_endrep.insert(c_endrep.begin() + 1, 1, slash);
	
	c_ack.push_back((uint8_t) '<');
	c_ack.push_back((uint8_t) 'A');
	c_ack.push_back((uint8_t) 'C');
	c_ack.push_back((uint8_t) 'K');
	c_ack.push_back((uint8_t) '>');
	
	c_auth.push_back((uint8_t) '<');
	c_auth.push_back((uint8_t) 'A');
	c_auth.push_back((uint8_t) 'U');
	c_auth.push_back((uint8_t) 'T');
	c_auth.push_back((uint8_t) 'H');
	c_auth.push_back((uint8_t) '>');
	
	c_endauth = c_auth;
	c_endauth.insert(c_endauth.begin() + 1, 1, slash);
	
	c_sid.push_back((uint8_t) '<');
	c_sid.push_back((uint8_t) 'S');
	c_sid.push_back((uint8_t) 'I');
	c_sid.push_back((uint8_t) 'D');
	c_sid.push_back((uint8_t) '>');
	
	c_endsid = c_sid;
	c_endsid.insert(c_endsid.begin() + 1, 1, slash);
}

/**********************************************************************************************
 * accept - simply calls the acceptFD FileDesc method to accept a connection on a server socket.
 *
 *    Params: server - an open/bound server file descriptor with an available connection
 *
 *    Throws: socket_error for recoverable errors, runtime_error for unrecoverable types
 **********************************************************************************************/

bool TCPConn::accept(SocketFD &server) {
	// Accept the connection
	bool results = _connfd.acceptFD(server);
	_connfd.setNonBlocking();
	
	
	// Set the state as waiting for the authorization packet
	_status = s_connected;
	_connected = true;
	return results;
}

/**********************************************************************************************
 * sendData - sends the data in the parameter to the socket
 *
 *    Params:  msg - the string to be sent
 *             size - if we know how much data we should expect to send, this should be populated
 *
 *    Throws: runtime_error for unrecoverable errors
 **********************************************************************************************/

bool TCPConn::sendData(std::vector<uint8_t> &buf) {
	
	_connfd.writeBytes<uint8_t>(buf);
	
	return true;
}

/**********************************************************************************************
 * encryptData - block encrypts data and places the results in the buffer in <ID><Data> format
 *
 *    Params:  buf - where to place the <IV><Data> stream
 *
 *    Throws: runtime_error for unrecoverable errors
 **********************************************************************************************/

void TCPConn::encryptData(std::vector<uint8_t> &buf) {
	// For the initialization vector
	SecByteBlock init_vector(iv_size);
	AutoSeededRandomPool rnd;
	
	// Generate our random init vector
	rnd.GenerateBlock(init_vector, init_vector.size());
	
	// Encrypt the data
	CFB_Mode<AES>::Encryption encryptor;
	encryptor.SetKeyWithIV(_aes_key, _aes_key.size(), init_vector);
	
	std::string cipher;
	ArraySource as(buf.data(), buf.size(), true, new StreamTransformationFilter(encryptor, new StringSink(cipher)));
	
	// Now add the IV to the stream we will be sending out
	std::vector<uint8_t> enc_data(init_vector.begin(), init_vector.end());
	enc_data.insert(enc_data.end(), cipher.begin(), cipher.end());
	buf = enc_data;
}

/**********************************************************************************************
 * handleConnection - performs a check of the connection, looking for data on the socket and
 *                    handling it based on the _status, or stage, of the connection
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::handleConnection() {
	try {
		std::optional<std::vector<uint8_t>> packet;
		while ((packet = getPacket())) {
			switch (_status) {
				// Client: Just connected, send our SID
				case s_connecting:
					sendSID(*packet);
					break;
					// Server: Wait for the SID from a newly-connected client, then send our SID
				case s_connected:
					receiveSID(*packet);
					break;
					// Client: connecting user - replicate data
				case s_datatx:
					transmitData(*packet);
					break;
					// Server: Receive data from the client
				case s_datarx:
					waitForData(*packet);
					break;
					// Client: Wait for acknowledgement that data sent was received before disconnecting
				case s_waitack:
					awaitAck(*packet);
					break;
				case s_auth2:
					handleAuth2(*packet);
					break;
				case s_auth3:
					handleAuth3(*packet);
					break;
				case s_auth4:
					handleAuth4(*packet);
					break;
					// Server: Data received and conn disconnected, but waiting for the data to be retrieved
				case s_hasdata:
					break;
				default:
					throw std::runtime_error("Invalid connection status!");
			}
		}
	} catch (socket_error &e) {
		std::cout << "Socket error, disconnecting.\n";
		disconnect();
		return;
	}
	
}

/**********************************************************************************************
 * sendSID()  - Client: after a connection, client sends its Server ID to the server
 *
 *    Throws: socket_error for network issues, runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::sendSID(const std::vector<uint8_t> &recvBuf) {
	std::vector<uint8_t> buf(_svr_id.begin(), _svr_id.end());
	wrapCmd(buf, c_sid, c_endsid);
	sendData(buf);
	
	_status = s_auth2;
}

/**********************************************************************************************
 * waitForSID()  - receives the SID and sends our SID
 *
 *    Throws: socket_error for network issues, runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::receiveSID(const std::vector<uint8_t> &recvBuf) {
	std::string node(recvBuf.begin(), recvBuf.end());
	setNodeID(node.c_str());
	
	sendRandomBytes();
	_status = s_auth3;
}


/**********************************************************************************************
 * transmitData()  - receives the SID from the server and transmits data
 *
 *    Throws: socket_error for network issues, runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::transmitData(const std::vector<uint8_t> &recvBuf) {
	std::string node(recvBuf.begin(), recvBuf.end());
	setNodeID(node.c_str());
	
	// Send the replication data
	sendData(_outputbuf);
	
	if (_verbosity >= 3)
		std::cout << "Successfully authenticated connection with " << getNodeID() << " and sending replication data.\n";
	
	// Wait for their response
	_status = s_waitack;
}


/**********************************************************************************************
 * waitForData - receiving server, authentication complete, wait for replication datai
               Also sends a plaintext random auth string of our own
 *
 *    Throws: socket_error for network issues, runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::waitForData(const std::vector<uint8_t> &recvBuf) {
	_inputbuf = recvBuf;
	_data_ready = true;
	
	// Send the acknowledgement and disconnect
	sendData(c_ack);
	
	if (_verbosity >= 2)
		std::cout << "Successfully received replication data from " << getNodeID() << "\n";
	
	_status = s_hasdata;
}


/**********************************************************************************************
 * awaitAwk - waits for the awk that data was received and disconnects
 *
 *    Throws: socket_error for network issues, runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::awaitAck(const std::vector<uint8_t> &recvBuf) {
	if (_verbosity >= 3)
		std::cout << "Data ack received from " << getNodeID() << ". Disconnecting.\n";
	
	disconnect();
}

void TCPConn::handleAuth2(const std::vector<uint8_t> &recvBuf) {
	// TODO: RX random bytes
	auto rxRandomBytes = std::array<uint8_t, RANDOM_BYTE_COUNT>{};
	std::copy(recvBuf.begin(), recvBuf.end(), rxRandomBytes.begin());
	// TODO: TX random bytes
	// TODO: TX encrypted bytes
	sendRandomAndEncryptedBytes(rxRandomBytes);
	_status = s_auth4;
}

void TCPConn::handleAuth3(const std::vector<uint8_t> &recvBuf) {
	// RX random bytes
	auto rxRandomBytes = std::array<uint8_t, RANDOM_BYTE_COUNT>{};
	std::copy(recvBuf.begin(), recvBuf.begin() + RANDOM_BYTE_COUNT, rxRandomBytes.begin());
	// RX encrypted bytes
	auto rxEncryptedBytesEncrypted = std::vector<uint8_t>(recvBuf.begin() + RANDOM_BYTE_COUNT, recvBuf.end());
	decryptData(rxEncryptedBytesEncrypted);
	std::array<uint8_t, RANDOM_BYTE_COUNT> rxEncryptedBytes{};
	std::copy(rxEncryptedBytesEncrypted.begin(), rxEncryptedBytesEncrypted.begin() + RANDOM_BYTE_COUNT, rxEncryptedBytes.begin());
	// TODO: verify encrypted bytes
	if (!std::equal(_authstr.begin(), _authstr.end(), rxEncryptedBytes.begin())) {
		std::cerr << "Failed authentication check. Disconnecting..." << std::endl;
		disconnect();
		return;
	}
	sendEncryptedBytes(rxRandomBytes);
	
	_status = s_datarx;
	std::vector<uint8_t> sidBuffer(_svr_id.begin(), _svr_id.end());
	wrapCmd(sidBuffer, c_sid, c_endsid);
	sendData(sidBuffer);
}

void TCPConn::handleAuth4(const std::vector<uint8_t> &recvBuf) {
	// TODO: RX encrypted bytes
	auto buf = recvBuf;
	decryptData(buf);
	std::array<uint8_t, RANDOM_BYTE_COUNT> rxEncryptedBytes{};
	std::copy(buf.begin(), buf.end(), rxEncryptedBytes.begin());
	// TODO: verify encrypted bytes
	if (!std::equal(_authstr.begin(), _authstr.end(), rxEncryptedBytes.begin())) {
		std::cerr << "Failed authentication check. Disconnecting..." << std::endl;
		disconnect();
		return;
	}
	_status = s_datatx;
}

void TCPConn::sendRandomBytes() {
	createRandomBytes();
	auto buf = std::vector<uint8_t>(RANDOM_BYTE_COUNT);
	std::copy(_authstr.begin(), _authstr.end(), buf.begin());
	wrapCmd(buf, c_auth, c_endauth);
	sendData(buf);
}

void TCPConn::sendEncryptedBytes(const std::array<uint8_t, RANDOM_BYTE_COUNT> &randomBytes) {
	auto bytes = std::vector<uint8_t>(randomBytes.begin(), randomBytes.end());
	encryptData(bytes);
	wrapCmd(bytes, c_auth, c_endauth);
	sendData(bytes);
}

void TCPConn::sendRandomAndEncryptedBytes(const std::array<uint8_t, RANDOM_BYTE_COUNT> &randomBytes) {
	auto bytes = std::vector<uint8_t>(randomBytes.begin(), randomBytes.end());
	encryptData(bytes);
	
	createRandomBytes();
	auto buf = std::vector<uint8_t>(RANDOM_BYTE_COUNT + bytes.size());
	std::copy(_authstr.begin(), _authstr.end(), buf.begin());
	std::copy(bytes.begin(), bytes.end(), buf.begin() + RANDOM_BYTE_COUNT);
	wrapCmd(buf, c_auth, c_endauth);
	sendData(buf);
}

void TCPConn::createRandomBytes() {
	std::default_random_engine generator{std::random_device{}()};
	std::uniform_int_distribution<uint8_t> distribution(0, 255);
	
	for (auto &r : _authstr)
		r = distribution(generator);
}


/**********************************************************************************************
 * decryptData - Takes in an encrypted buffer in the form IV/Data and decrypts it, replacing
 *               buf with the decrypted info (destroys IV string>
 *
 *    Params: buf - the encrypted string and holds the decrypted data (minus IV)
 *
 **********************************************************************************************/
void TCPConn::decryptData(std::vector<uint8_t> &buf) {
	// For the initialization vector
	SecByteBlock init_vector(iv_size);
	
	// Copy the IV from the incoming stream of data
	init_vector.Assign(buf.data(), iv_size);
	buf.erase(buf.begin(), buf.begin() + iv_size);
	
	// Decrypt the data
	CFB_Mode<AES>::Decryption decryptor;
	decryptor.SetKeyWithIV(_aes_key, _aes_key.size(), init_vector);
	
	std::string recovered;
	ArraySource as(buf.data(), buf.size(), true, new StreamTransformationFilter(decryptor, new StringSink(recovered)));
	
	buf.assign(recovered.begin(), recovered.end());
	
}

/**********************************************************************************************
 * getData - Reads in data from the socket and checks to see if there's an end command to the
 *           message to confirm we got it all
 *
 *    Params: None - data is stored in _inputbuf for retrieval with GetInputData
 *
 *    Returns: true if the data is ready to be read, false if they lost connection
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

bool TCPConn::getData() {
	std::array<uint8_t, 1024> readbuf = {};
	int n;
	while ((n = read(_connfd.getFD(), readbuf.data(), readbuf.size())) > 0) {
		_buf.insert(_buf.end(), readbuf.begin(), readbuf.begin() + n);
	}
	return !_buf.empty();
}


std::optional<std::vector<uint8_t>> TCPConn::getPacket() {
	if (getData())
		return getCmdData(getStateStartEnd(_status));
	if (_status == s_connecting)
		return std::vector<uint8_t>{};
	return std::nullopt;
}

/**********************************************************************************************
 * getCmdData - looks for a startcmd and endcmd and returns the data between the two
 *
 *    Params: buf = the string to search for the tags
 *            startcmd - the command at the beginning of the data sought
 *            endcmd - the command at the end of the data sought
 *
 *    Returns: true if both start and end commands were found, false otherwisei
 *
 **********************************************************************************************/

std::optional<std::vector<uint8_t>> TCPConn::getCmdData(std::pair<std::vector<uint8_t>, std::vector<uint8_t>> cmd) {
	auto &startcmd = std::get<0>(cmd);
	auto &endcmd = std::get<1>(cmd);
	if (startcmd.empty())
		return std::make_optional(std::vector<uint8_t>{});
	
	auto start = std::search(_buf.begin(), _buf.end(), cmd.first.begin(), cmd.first.end());
	auto end = std::search(_buf.begin(), _buf.end(), cmd.second.begin(), cmd.second.end());
	
	assert(start == _buf.begin());
	if (start != _buf.end() && endcmd.empty()) {
		_buf.erase(start, start + startcmd.size());
		return std::make_optional(std::vector<uint8_t>{});
	}
	
	if ((start == _buf.end()) || (end == _buf.end()))
		return std::nullopt;
	
	auto ret = std::make_optional(std::vector<uint8_t>(start + startcmd.size(), end));
	_buf.erase(_buf.begin(), end + endcmd.size());
	return ret;
}

/**********************************************************************************************
 * wrapCmd - wraps the command brackets around the passed-in data
 *
 *    Params: buf = the string to wrap around
 *            startcmd - the command at the beginning of the data
 *            endcmd - the command at the end of the data
 *
 **********************************************************************************************/

void TCPConn::wrapCmd(std::vector<uint8_t> &buf, std::vector<uint8_t> &startcmd, std::vector<uint8_t> &endcmd) {
	buf.insert(buf.begin(), startcmd.begin(), startcmd.end());
	buf.insert(buf.end(), endcmd.begin(), endcmd.end());
}

/**********************************************************************************************
 * getReplData - Returns the data received on the socket and marks the socket as done
 *
 *    Params: buf = the data received
 *
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::getInputData(std::vector<uint8_t> &buf) {
	
	// Returns the replication data off this connection, then prepares it to be removed
	buf = _inputbuf;
	
	_data_ready = false;
	_status = s_none;
}


/**********************************************************************************************
 * connect - Opens the socket FD, attempting to connect to the remote server
 *
 *    Params:  ip_addr - ip address string to connect to
 *             port - port in host format to connect to
 *
 *    Throws: socket_error exception if failed. socket_error is a child class of runtime_error
 **********************************************************************************************/

void TCPConn::connect(const char *ip_addr, unsigned short port) {
	
	// Set the status to connecting
	_status = s_connecting;
	
	// Try to connect
	if (!_connfd.connectTo(ip_addr, port))
		throw socket_error("TCP Connection failed!");
	
	_connfd.setNonBlocking();
	_connected = true;
}


// Same as above, but ip_addr and port are in network (big endian) format
void TCPConn::connect(unsigned long ip_addr, unsigned short port) {
	// Set the status to connecting
	_status = s_connecting;
	
	if (!_connfd.connectTo(ip_addr, port))
		throw socket_error("TCP Connection failed!");
	
	_connfd.setNonBlocking();
	_connected = true;
}

/**********************************************************************************************
 * assignOutgoingData - sets up the connection so that, at the next handleConnection, the data
 *                      is sent to the target server
 *
 *    Params:  data - the data stream to send to the server
 *
 **********************************************************************************************/

void TCPConn::assignOutgoingData(std::vector<uint8_t> &data) {
	
	_outputbuf.clear();
	_outputbuf = c_rep;
	_outputbuf.insert(_outputbuf.end(), data.begin(), data.end());
	_outputbuf.insert(_outputbuf.end(), c_endrep.begin(), c_endrep.end());
}

/**********************************************************************************************
 * disconnect - cleans up the socket as required and closes the FD
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/
void TCPConn::disconnect() {
	_connfd.closeFD();
	_connected = false;
}

/**********************************************************************************************
 * isConnected - performs a simple check on the socket to see if it is still open
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/
bool TCPConn::isConnected() {
	return _connected;
	// return _connfd.isOpen(); // This does not work very well
}

/**********************************************************************************************
 * getIPAddrStr - gets a string format of the IP address and loads it in buf
 *
 **********************************************************************************************/
const char *TCPConn::getIPAddrStr(std::string &buf) {
	_connfd.getIPAddrStr(buf);
	return buf.c_str();
}

std::pair<std::vector<uint8_t>, std::vector<uint8_t>> TCPConn::getStateStartEnd(TCPConn::statustype status) {
	switch (status) {
		case s_none:
		case s_connecting:
			return std::pair{std::vector<uint8_t>{}, std::vector<uint8_t>{}};
		case s_connected:
		case s_datatx:
			return std::pair{c_sid, c_endsid};
		case s_datarx:
			return std::pair{c_rep, c_endrep};
		case s_waitack:
			return std::pair{c_ack, std::vector<uint8_t>{}};
		case s_hasdata:
			return std::pair{std::vector<uint8_t>{}, std::vector<uint8_t>{}};
		case s_auth2:
		case s_auth3:
		case s_auth4:
			return std::pair{c_auth, c_endauth};
	}
	return std::pair<std::vector<uint8_t>, std::vector<uint8_t>>();
}
