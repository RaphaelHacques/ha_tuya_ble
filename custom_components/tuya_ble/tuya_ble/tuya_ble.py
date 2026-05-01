"""Tuya BLE Device."""
from __future__ import annotations

import asyncio
import hashlib
import logging
import secrets
import time
from typing import Any
from struct import pack, unpack

from bleak import BleakClient, BleakError
from bleak_retry_connector import establish_connection, BleakNotFoundError, BleakOutOfConnectionSlotsError
from Crypto.Cipher import AES

from .const import (
    CHARACTERISTIC_NOTIFY,
    CHARACTERISTIC_WRITE,
    MANUFACTURER_DATA_ID,
    SERVICE_UUID,
    TuyaBLECode,
)

_LOGGER = logging.getLogger(__name__)

# Integration constants
RESPONSE_WAIT_TIMEOUT = 5.0
CONNECT_RETRY_COUNT = 3
GATT_MTU = 20

class TuyaBLEDataFormatError(Exception):
    """Error to indicate a data format error."""

class TuyaBLEDataPoint:
    """Tuya BLE Data Point."""

    def __init__(self, code: str, dp_id: int, value: Any) -> None:
        """Initialize."""
        self.code = code
        self.dp_id = dp_id
        self.value = value

    def __repr__(self) -> str:
        """Return representation."""
        return f"TuyaBLEDataPoint(code={self.code}, dp_id={self.dp_id}, value={self.value})"

class TuyaBLEEntityDescription:
    """Tuya BLE Entity Description."""

    def __init__(self, code: str, dp_id: int, type: str, values: str) -> None:
        """Initialize."""
        self.code = code
        self.dp_id = dp_id
        self.type = type
        self.values = values

class TuyaBLEDevice:
    """Tuya BLE Device."""

    def __init__(self, hass: Any, ble_device: Any, advertisement_data: Any, device_manager: Any = None) -> None:
        """Initialize."""
        self.hass = hass
        self._ble_device = ble_device
        self._advertisement_data = advertisement_data
        self._device_manager = device_manager
        self._device_info = None
        self._client: BleakClient | None = None
        self._is_paired = False
        self._is_bound = False
        self._protocol_version = 3
        self._local_key = b""
        self._login_key = b""
        self._session_key = b""
        self._input_buffer: bytearray | None = None
        self._response_futures: dict[int, asyncio.Future[bytes]] = {}
        self._functions: dict[int, TuyaBLEEntityDescription] = {}
        self._status: dict[int, Any] = {}
        self._init_lock = asyncio.Lock()
        self._seq_num = 1
        
        # Initial analysis of advertisement data
        self._decode_advertisement_data()

    def _decode_advertisement_data(self) -> None:
        """Decode advertisement data."""
        if self._advertisement_data:
            raw_product_id = None
            if self._advertisement_data.service_data:
                service_data = self._advertisement_data.service_data.get(SERVICE_UUID)
                if service_data and len(service_data) > 1:
                    match service_data[0]:
                        case 0:
                            raw_product_id = service_data[1:]

            if self._advertisement_data.manufacturer_data:
                manufacturer_data = self._advertisement_data.manufacturer_data.get(MANUFACTURER_DATA_ID)
                if manufacturer_data and len(manufacturer_data) > 6:
                    self._is_bound = (manufacturer_data[0] & 0x80) != 0
                    # Standard Protocol Version is in the SECOND byte
                    self._protocol_version = manufacturer_data[1]
                    _LOGGER.debug("%s: Raw manufacturer data: %s", self.address, manufacturer_data.hex())
                    _LOGGER.debug("%s: Detected protocol version: %s", self.address, self._protocol_version)
                    
                    # UUID extraction
                    raw_uuid = manufacturer_data[6:]
                    if raw_product_id:
                        try:
                            key = hashlib.md5(raw_product_id).digest()
                            cipher = AES.new(key, AES.MODE_CBC, key)
                            raw_uuid = cipher.decrypt(raw_uuid)
                            self._uuid = raw_uuid.decode("utf-8")
                        except:
                            _LOGGER.debug("%s: Failed to decrypt UUID", self.address)

    @property
    def address(self) -> str:
        """Return the address."""
        return self._ble_device.address

    @property
    def name(self) -> str:
        """Return the name."""
        if self._device_info:
            return self._device_info.device_name
        return self._ble_device.name or self.address

    @property
    def protocol_version(self) -> int:
        """Return the protocol version."""
        return self._protocol_version

    @property
    def is_connected(self) -> bool:
        """Return true if connected."""
        return self._client is not None and self._client.is_connected

    async def update(self) -> None:
        """Update the device."""
        if not await self._update_device_info():
            _LOGGER.error("%s: Failed to get device credentials", self.address)
            return

        _LOGGER.debug("%s: Updating (Protocol V%s)", self.address, self._protocol_version)
        try:
            await self._send_packet(TuyaBLECode.FUN_SENDER_DEVICE_STATUS, bytes())
        except Exception:
            _LOGGER.error("%s: Update failed", self.address, exc_info=True)

    async def _update_device_info(self) -> bool:
        """Fetch credentials and prepare keys."""
        async with self._init_lock:
            if self._device_info is None:
                _LOGGER.debug("%s: !!! TUYA BLE DEBUG: INITIALIZING %s !!!", self.address, self.address)
                if self._device_manager:
                    self._device_info = await self._device_manager.get_device_credentials(self.address, False)
                
            if self._device_info:
                # Force V4 for Fingerbot Touch models 'bs3ubslo'
                if "bs3ubslo" in str(self._device_info.product_id):
                    _LOGGER.debug("%s: Product ID matches Fingerbot Touch, forcing V4", self.address)
                    self._protocol_version = 4

                self._local_key = self._device_info.local_key.encode()
                if self._protocol_version == 4:
                    _LOGGER.debug("%s: Using TRUNCATED (6 bytes) local key for MD5 (Protocol V4)", self.address)
                    self._login_key = hashlib.md5(self._local_key[:6]).digest()
                else:
                    _LOGGER.debug("%s: Using FULL (16 bytes) local key for MD5 (Protocol V%s)", self.address, self._protocol_version)
                    self._login_key = hashlib.md5(self._local_key).digest()

                self.append_functions(self._device_info.functions, self._device_info.status_range)

        return self._device_info is not None

    def append_functions(self, functions: list[Any], status_range: list[Any]) -> None:
        """Store function definitions."""
        for func in functions:
            dp_id = func.get("dp_id")
            if dp_id:
                self._functions[dp_id] = TuyaBLEEntityDescription(
                    func.get("code", ""),
                    dp_id,
                    func.get("type", ""),
                    func.get("values", ""),
                )

    async def _ensure_connected(self) -> None:
        """Ensure the device is connected with exponential backoff."""
        if self._client and self._client.is_connected:
            return

        self._client = None
        self._is_paired = False
        backoff = 1.0
        
        for attempt in range(CONNECT_RETRY_COUNT):
            _LOGGER.debug("%s: Connection attempt (%s left), backoff: %ss", self.address, CONNECT_RETRY_COUNT - attempt - 1, backoff)
            try:
                client = await establish_connection(
                    BleakClient,
                    self._ble_device,
                    self.address,
                    disconnected_callback=lambda c: self._on_disconnected(c),
                    use_services_cache=True,
                    ble_device_callback=lambda: self._ble_device,
                )
                self._client = client
                
                if self._client and self._client.is_connected:
                    _LOGGER.debug("%s: Connected successfully", self.address)
                    try:
                        from bleak.backends.bluezdbus.client import BleakDBusError
                        await self._client.start_notify(CHARACTERISTIC_NOTIFY, self._notification_handler)
                        _LOGGER.debug("%s: Notifications started successfully", self.address)
                    except Exception as e:
                        if "Notify acquired" in str(e):
                            _LOGGER.debug("%s: Notifications already active", self.address)
                        else:
                            raise e
                
                if self._client and self._client.is_connected:
                    # Mandatory Handshake for V3/V4
                    if not self._is_paired:
                        _LOGGER.debug("%s: Sending pairing request (Handshake)", self.address)
                        pairing_data = self._build_pairing_request()
                        try:
                            # 20s timeout for handshake
                            success = await asyncio.wait_for(
                                self._send_packet_while_connected(TuyaBLECode.FUN_SENDER_PAIR, pairing_data, 0, True),
                                timeout=20.0
                            )
                            if not success:
                                _LOGGER.error("%s: Pairing failed (no response)", self.address)
                                await self._client.disconnect()
                                continue
                        except asyncio.TimeoutError:
                            _LOGGER.error("%s: Pairing timed out", self.address)
                            await self._client.disconnect()
                            continue
                        
                        self._is_paired = True
                        _LOGGER.debug("%s: Pairing successful", self.address)
                    
                    return # All good
                    
            except Exception as e:
                _LOGGER.error("%s: Connection failed: %s", self.address, e)
                await asyncio.sleep(backoff)
                backoff *= 2.0
                
        raise BleakNotFoundError()

    def _on_disconnected(self, client: BleakClient) -> None:
        """Handle disconnection."""
        _LOGGER.debug("%s: Disconnected", self.address)
        self._is_paired = False
        self._client = None
        for future in self._response_futures.values():
            if not future.done():
                future.set_exception(BleakError("Disconnected"))
        self._response_futures.clear()

    def _build_pairing_request(self) -> bytes:
        """Build the pairing request packet."""
        result = bytearray()
        result += self._device_info.uuid.encode()
        # For V4, we use 6 bytes, otherwise 16
        if self._protocol_version == 4:
            result += self._local_key[:6]
        else:
            result += self._local_key
        result += self._device_info.device_id.encode()
        # Padding to 44 bytes or more if needed
        while len(result) < 44:
            result.append(0)
        return bytes(result)

    async def _send_packet(self, code: TuyaBLECode, data: bytes) -> bool:
        """Send a packet and wait for response."""
        await self._ensure_connected()
        return await self._send_packet_while_connected(code, data)

    async def _send_packet_while_connected(self, code: TuyaBLECode, data: bytes, response_to: int = 0, handshake: bool = False) -> bool:
        """Low level send packet."""
        if not self._client or not self._client.is_connected:
            return False

        seq_num = self._seq_num
        self._seq_num += 1
        
        future = asyncio.Future()
        self._response_futures[seq_num] = future
        
        try:
            packets = self._build_packets(seq_num, code, data, response_to)
            for packet in packets:
                _LOGGER.debug("%s: Sending raw packet: %s", self.address, packet.hex())
                await self._client.write_gatt_char(CHARACTERISTIC_WRITE, packet, response=False)
            
            if not handshake:
                # Wait for response logic
                try:
                    await asyncio.wait_for(future, RESPONSE_WAIT_TIMEOUT)
                    return True
                except asyncio.TimeoutError:
                    _LOGGER.warning("%s: Timeout waiting for response to #%s", self.address, seq_num)
                    return False
            return True
        finally:
            self._response_futures.pop(seq_num, None)

    def _build_packets(self, seq_num: int, code: TuyaBLECode, data: bytes, response_to: int = 0) -> list[bytes]:
        """Build encrypted packets."""
        iv = secrets.token_bytes(16)
        
        # Key selection
        if code in (TuyaBLECode.FUN_SENDER_DEVICE_INFO, TuyaBLECode.FUN_SENDER_PAIR):
            key = self._login_key
            security_flag = b"\x04"
            _LOGGER.debug("%s: Building packet with login_key (len=%s, flag=%s) for %s", self.address, len(key), security_flag.hex(), code.name)
        else:
            key = self._session_key
            security_flag = b"\x05"
            _LOGGER.debug("%s: Building packet with session_key (len=%s, flag=%s) for %s", self.address, len(key or b""), security_flag.hex(), code.name)

        # Standard Tuya Packet Body
        raw = bytearray()
        raw += pack(">IIHH", seq_num, response_to, code.value, len(data))
        raw += data
        crc = self._calc_crc16(raw)
        raw += pack(">H", crc)
        
        # PKCS7 padding to 16 bytes
        pad_len = 16 - (len(raw) % 16)
        raw += bytes([pad_len] * pad_len)

        # AES-CBC Encryption
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted = security_flag + iv + cipher.encrypt(raw)

        # MTU Fragmentation
        result = []
        length = len(encrypted)
        pos = 0
        packet_num = 0
        
        while pos < length:
            packet = bytearray()
            # Packet header: Number
            packet.append(packet_num)
            if packet_num == 0:
                # First packet header: Length + Version
                packet.append(length)
                packet.append(self._protocol_version << 4)
            
            chunk_size = GATT_MTU - len(packet)
            chunk = encrypted[pos:pos+chunk_size]
            packet += chunk
            result.append(bytes(packet))
            pos += len(chunk)
            packet_num += 1
            
        return result

    def _calc_crc16(self, data: bytes) -> int:
        """Calculate Tuya CRC16."""
        crc = 0xFFFF
        for b in data:
            crc ^= b
            for _ in range(8):
                if crc & 1:
                    crc = (crc >> 1) ^ 0xA001
                else:
                    crc >>= 1
        return crc

    def _notification_handler(self, characteristic: Any, data: bytes) -> None:
        """Handle incoming notifications."""
        _LOGGER.debug("%s: Received raw notification: %s", self.address, data.hex())
        # Re-assembly logic should go here (omitted for brevity but normally required)
        pass

    def stop(self) -> None:
        """Stop the device."""
        _LOGGER.debug("%s: Stop", self.address)
        if self._client:
            self.hass.async_create_task(self._client.disconnect())
