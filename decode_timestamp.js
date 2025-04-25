/**
 * Script giải mã timestamp từ dữ liệu của nhẫn thông minh
 * 
 * Nhẫn thông minh sử dụng timestamp tính từ 01/01/2000 00:00:00 UTC
 * và lưu trữ dưới dạng 4 byte theo thứ tự little-endian
 */

// Hằng số Unix timestamp cho 01/01/2000 00:00:00 UTC
const EPOCH_2000_UNIX_TIMESTAMP = 946684800;

/**
 * Giải mã timestamp từ 4 byte dữ liệu của nhẫn thông minh
 * 
 * @param {Array<number>} bytes - Mảng 4 byte dạng little-endian (LSB first)
 * @param {number} timezoneOffset - Độ lệch múi giờ tính bằng giờ (VD: 7 cho GMT+7)
 * @returns {Object} Đối tượng chứa timestamp và thời gian đã định dạng
 */
function decodeTimestamp(bytes, timezoneOffset = 7) {
  // Chuyển 4 byte thành số nguyên theo little-endian
  const rawTimestamp = 
    (bytes[0] & 0xFF) + 
    ((bytes[1] & 0xFF) << 8) + 
    ((bytes[2] & 0xFF) << 16) + 
    ((bytes[3] & 0xFF) << 24);
  
  // Cộng với Unix timestamp của 01/01/2000
  const unixSeconds = rawTimestamp + EPOCH_2000_UNIX_TIMESTAMP;
  
  // Chuyển sang milliseconds
  const unixMilliseconds = unixSeconds * 1000;
  
  // Tạo đối tượng Date
  const date = new Date(unixMilliseconds);
  
  // Điều chỉnh múi giờ
  const timezoneOffsetMillis = timezoneOffset * 60 * 60 * 1000;
  const localDate = new Date(unixMilliseconds + (timezoneOffsetMillis - date.getTimezoneOffset() * 60 * 1000));
  
  // Định dạng thời gian
  const formattedDate = localDate.toLocaleString('vi-VN', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false
  });
  
  return {
    rawTimestamp: rawTimestamp,
    unixTimestamp: unixSeconds,
    date: localDate,
    formatted: formattedDate
  };
}

/**
 * Giải mã dữ liệu nhịp tim từ dữ liệu thô
 * 
 * @param {string} hexString - Chuỗi hex của dữ liệu thô
 * @param {number} timezoneOffset - Độ lệch múi giờ tính bằng giờ
 * @returns {Array<Object>} Mảng các đối tượng chứa thông tin đã giải mã
 */
function decodeHeartRateData(hexString, timezoneOffset = 7) {
  // Loại bỏ khoảng trắng và phân tách chuỗi hex thành mảng byte
  const hexBytes = hexString.replace(/\s+/g, '').match(/.{1,2}/g).map(hex => parseInt(hex, 16));
  
  const results = [];
  
  // Mỗi bản ghi nhịp tim là 6 byte: 4 byte timestamp + 1 byte heartRate + 1 byte thừa
  for (let i = 0; i < hexBytes.length; i += 6) {
    if (i + 5 < hexBytes.length) {
      const timestampBytes = hexBytes.slice(i, i + 4);
      const heartRate = hexBytes[i + 4]; // Byte thứ 5 là nhịp tim
      
      const timestamp = decodeTimestamp(timestampBytes, timezoneOffset);
      
      results.push({
        timestamp: timestamp,
        heartRate: heartRate,
        summary: `Thời gian: ${timestamp.formatted}, Nhịp tim: ${heartRate} BPM`
      });
    }
  }
  
  return results;
}

/**
 * Giải mã dữ liệu huyết áp từ dữ liệu thô
 * 
 * @param {string} hexString - Chuỗi hex của dữ liệu thô
 * @param {number} timezoneOffset - Độ lệch múi giờ tính bằng giờ
 * @returns {Array<Object>} Mảng các đối tượng chứa thông tin đã giải mã
 */
function decodeBloodPressureData(hexString, timezoneOffset = 7) {
  // Loại bỏ khoảng trắng và phân tách chuỗi hex thành mảng byte
  const hexBytes = hexString.replace(/\s+/g, '').match(/.{1,2}/g).map(hex => parseInt(hex, 16));
  
  const results = [];
  
  // Mỗi bản ghi huyết áp là 8 byte: 4 byte timestamp + 1 byte isInflated + 1 byte SBP + 1 byte DBP + 1 byte thừa
  for (let i = 0; i < hexBytes.length; i += 8) {
    if (i + 7 < hexBytes.length) {
      const timestampBytes = hexBytes.slice(i, i + 4);
      const isInflated = hexBytes[i + 4]; // Byte thứ 5 là chỉ báo loại đo
      const sbp = hexBytes[i + 5]; // Byte thứ 6 là huyết áp tâm thu
      const dbp = hexBytes[i + 6]; // Byte thứ 7 là huyết áp tâm trương
      
      const timestamp = decodeTimestamp(timestampBytes, timezoneOffset);
      
      results.push({
        timestamp: timestamp,
        isInflated: isInflated === 1,
        sbp: sbp,
        dbp: dbp,
        summary: `Thời gian: ${timestamp.formatted}, Huyết áp: ${sbp}/${dbp} mmHg, ${isInflated === 1 ? 'Đo bơm hơi' : 'Đo không bơm hơi'}`
      });
    }
  }
  
  return results;
}

// Phân tích dữ liệu từ log.md
const heartRateHexData = "a7 49 9c 2f 00 57 c9 57 9c 2f 00 51 cf 65 9c 2f 00 38 d7 73 9c 2f 00 4c e4 81 9c 2f 00 49 fe 8f 9c 2f 00 49 12 9e 9c 2f 00 48 15 ac 9c 2f 00 4a";
const bloodPressureHexData = "a7 49 9c 2f 01 73 4a 57 c9 57 9c 2f 01 72 4a 51 cf 65 9c 2f 01 69 44 38 d7 73 9c 2f 01 6e 4a 4c e4 81 9c 2f 01 6e 49 49 fe 8f 9c 2f 01 6c 49 49 12 9e 9c 2f 01 6d 49 48 15 ac 9c 2f 01 6f 47 4a";

// Giải mã dữ liệu nhịp tim
const heartRateResults = decodeHeartRateData(heartRateHexData);
console.log("=== Dữ liệu nhịp tim ===");
heartRateResults.forEach((result, index) => {
  console.log(`[${index + 1}] ${result.summary}`);
});

// Giải mã dữ liệu huyết áp
const bloodPressureResults = decodeBloodPressureData(bloodPressureHexData);
console.log("\n=== Dữ liệu huyết áp ===");
bloodPressureResults.forEach((result, index) => {
  console.log(`[${index + 1}] ${result.summary}`);
});

// Chạy với node: node decode_timestamp.js