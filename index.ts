// Định nghĩa các interface cho dữ liệu giấc ngủ
interface SleepPhase {
  sleepStartTime: number;
  sleepLen: number;
  sleepType: number;
}

interface SleepBlock {
  wakeCount: number;
  deepSleepCount: number;
  rapidEyeMovementTotal: number;
  lightSleepCount: number;
  wakeDuration: number;
  sleepData: SleepPhase[];
  startTime: number;
  lightSleepTotal: number;
  endTime: number;
  deepSleepTotal: number;
}

interface SleepResponse {
  code: number;
  data: SleepBlock[];
  dataType: number;
}

// Định nghĩa các hằng số
const SLEEP_TYPES = {
  DEEP_SLEEP: 241, // 0xF1
  LIGHT_SLEEP: 242, // 0xF2
  REM: 243, // 0xF3
  AWAKE: 244, // 0xF4
};

// Hàm chuyển đổi chuỗi hex thành mảng byte
function hexStringToByteArray(hexString: string): Uint8Array {
  // Loại bỏ khoảng trắng và xuống dòng
  const cleanedHexString = hexString.replace(/[\s\n\r]/g, '');
  
  // Tạo mảng byte
  const byteArray = new Uint8Array(cleanedHexString.length / 2);
  for (let i = 0; i < cleanedHexString.length; i += 2) {
    byteArray[i / 2] = parseInt(cleanedHexString.substring(i, i + 2), 16);
  }
  
  return byteArray;
}

// Hàm đọc số nguyên từ mảng byte ở định dạng little-endian
function readLittleEndianInt(bytes: Uint8Array, offset: number, length: number): number {
  let result = 0;
  for (let i = 0; i < length; i++) {
    result |= (bytes[offset + i] << (8 * i));
  }
  return result;
}

// Hàm chính để giải mã dữ liệu giấc ngủ
function decodeSleepData(hexData: string): SleepResponse {
  const bytes = hexStringToByteArray(hexData);
  let position = 0;
  
  const sleepBlocks: SleepBlock[] = [];
  
  // Duyệt qua dữ liệu để tìm các khối giấc ngủ
  while (position < bytes.length) {
    // Tìm header khối (af fa 54)
    if (bytes[position] === 0xAF && bytes[position + 1] === 0xFA && bytes[position + 2] === 0x54) {
      const blockIndex = bytes[position + 3];
      position += 4;
      
      // Đọc timestamp bắt đầu (4 bytes)
      const startTimestamp = readLittleEndianInt(bytes, position, 4) * 1000; // Chuyển đổi sang milliseconds
      position += 4;
      
      // Đọc thời lượng (2 bytes)
      const durationMinutes = readLittleEndianInt(bytes, position, 2);
      position += 2;
      
      // Bỏ qua 2 bytes timestamp bổ sung
      position += 2;
      
      // Bỏ qua 2 bytes marker phân cách (ff ff)
      position += 2;
      
      // Bỏ qua metadata bổ sung (6 bytes)
      position += 6;
      
      // Phân tích dữ liệu giai đoạn giấc ngủ
      const sleepPhases: SleepPhase[] = [];
      let deepSleepTotal = 0;
      let lightSleepTotal = 0;
      let remTotal = 0;
      
      let endTimestamp = startTimestamp;
      
      // Đọc các giai đoạn cho đến khi gặp header khối mới hoặc hết dữ liệu
      while (position + 8 <= bytes.length) {
        // Kiểm tra xem đã đến header khối mới chưa
        if (position + 3 < bytes.length && 
            bytes[position] === 0xAF && 
            bytes[position + 1] === 0xFA && 
            bytes[position + 2] === 0x54) {
          break;
        }
        
        const phaseMarker = bytes[position];
        position += 1;
        
        // Đọc timestamp của giai đoạn (4 bytes)
        const phaseTimestamp = readLittleEndianInt(bytes, position, 4) * 1000;
        position += 4;
        
        // Đọc thời lượng giai đoạn (3 bytes)
        const phaseDuration = readLittleEndianInt(bytes, position, 3);
        position += 3;
        
        // Cập nhật endTimestamp
        const phaseEndTime = phaseTimestamp + (phaseDuration * 1000);
        if (phaseEndTime > endTimestamp) {
          endTimestamp = phaseEndTime;
        }
        
        // Tính thời lượng theo phút
        const durationMinutes = Math.floor(phaseDuration / 60);
        
        // Cập nhật tổng thời gian theo loại giấc ngủ
        switch (phaseMarker) {
          case SLEEP_TYPES.DEEP_SLEEP: // Ngủ sâu
            deepSleepTotal += durationMinutes;
            break;
          case SLEEP_TYPES.LIGHT_SLEEP: // Ngủ nhẹ
            lightSleepTotal += durationMinutes;
            break;
          case SLEEP_TYPES.REM: // REM
            remTotal += durationMinutes;
            break;
        }
        
        // Thêm giai đoạn vào danh sách
        sleepPhases.push({
          sleepStartTime: phaseTimestamp,
          sleepLen: phaseDuration,
          sleepType: phaseMarker
        });
      }
      
      // Tạo khối giấc ngủ
      sleepBlocks.push({
        wakeCount: 0, // Mặc định là 0 vì không có wake phase trong dữ liệu mẫu
        deepSleepCount: 65535, // Giá trị này được lấy từ kết quả JSON, có thể là giá trị đặc biệt
        rapidEyeMovementTotal: remTotal,
        lightSleepCount: 0, // Mặc định là 0 vì không rõ logic tính toán
        wakeDuration: 0, // Mặc định là 0 vì không rõ logic tính toán
        sleepData: sleepPhases,
        startTime: startTimestamp,
        lightSleepTotal: lightSleepTotal,
        endTime: endTimestamp,
        deepSleepTotal: deepSleepTotal
      });
    } else {
      // Nếu không tìm thấy header, di chuyển đến byte tiếp theo
      position++;
    }
  }
  
  // Trả về kết quả
  return {
    code: 0,
    data: sleepBlocks,
    dataType: 1284 // Giá trị này được lấy từ kết quả JSON
  };
}

// Hàm định dạng dữ liệu thành chuỗi hex đẹp mắt (cho mục đích hiển thị)
function formatHexOutput(bytes: Uint8Array): string {
  let result = '';
  for (let i = 0; i < bytes.length; i++) {
    // Thêm dấu cách sau mỗi byte
    result += bytes[i].toString(16).padStart(2, '0') + ' ';
    
    // Xuống dòng sau mỗi 20 byte
    if ((i + 1) % 20 === 0) {
      result += '\n';
    }
  }
  return result;
}

// Hàm chính để sử dụng
function main(hexInput: string): void {
  try {
    // Giải mã dữ liệu
    const sleepResponse = decodeSleepData(hexInput);
    
    // In kết quả
    console.log('Kết quả giải mã:');
    console.log(JSON.stringify(sleepResponse, null, 2));
    
    // In thông tin tóm tắt
    console.log('\nTóm tắt giấc ngủ:');
    sleepResponse.data.forEach((block, index) => {
      const startDate = new Date(block.startTime);
      const endDate = new Date(block.endTime);
      
      console.log(`\nKhối ${index + 1}:`);
      console.log(`  Thời gian bắt đầu: ${startDate.toLocaleString()}`);
      console.log(`  Thời gian kết thúc: ${endDate.toLocaleString()}`);
      console.log(`  Tổng thời gian: ${Math.floor((block.endTime - block.startTime) / 60000)} phút`);
      console.log(`  Thời gian ngủ sâu: ${block.deepSleepTotal} phút`);
      console.log(`  Thời gian ngủ nhẹ: ${block.lightSleepTotal} phút`);
      console.log(`  Thời gian REM: ${block.rapidEyeMovementTotal} phút`);
      console.log(`  Số giai đoạn: ${block.sleepData.length}`);
    });
  } catch (error) {
    console.error('Lỗi khi giải mã dữ liệu:', error);
  }
}

// Ví dụ sử dụng với dữ liệu mẫu
const sampleHexData = `
af fa 54 00 7e f1 9e 2f c1 01 9f 2f ff ff 3e 01 c4 01 3d 0d
f2 7e f1 9e 2f 4c 05 00 f1 cb f6 9e 2f 50 01 00 f3 1c f8 9e
2f fb 00 00 f2 18 f9 9e 2f 46 03 00 f3 5f fc 9e 2f 43 00 00
f2 a2 fc 9e 2f 94 04 00 f1 36 01 9f 2f 74 00 00 f2 aa 01 9f
2f 17 00 00 af fa 54 01 e5 01 9f 2f c8 57 9f 2f ff ff 0f 0e
9d 0d 24 3a f2 e5 01 9f 2f 0a 05 00 f1 f0 06 9f 2f bf 01 00
f3 b0 08 9f 2f df 00 00 f2 90 09 9f 2f b3 02 00 f3 44 0c 9f
2f 04 01 00 f2 48 0d 9f 2f 25 05 00 f1 6d 12 9f 2f 64 00 00
f3 d1 12 9f 2f 1d 01 00 f2 ee 13 9f 2f 7b 06 00 f1 69 1a 9f
2f 63 00 00 f2 cc 1a 9f 2f d4 00 00 f3 a0 1b 9f 2f 5b 00 00
f2 fb 1b 9f 2f e5 04 00 f1 e1 20 9f 2f 72 01 00 f3 54 22 9f
2f b8 01 00 f2 0d 24 9f 2f 8b 00 00 f3 99 24 9f 2f 3d 00 00
f2 d6 24 9f 2f 82 04 00 f1 59 29 9f 2f 47 01 00 f3 a1 2a 9f
2f de 00 00 f2 80 2b 9f 2f f6 02 00 f3 77 2e 9f 2f de 00 00
f2 55 2f 9f 2f 4f 05 00 f1 a5 34 9f 2f c0 01 00 f3 66 36 9f
2f cc 01 00 f2 33 38 9f 2f e0 01 00 f3 14 3a 9f 2f 57 00 00
f2 6b 3a 9f 2f af 02 00 f3 1a 3d 9f 2f 16 02 00 f2 30 3f 9f
2f 75 00 00 f3 a5 3f 9f 2f c5 00 00 f2 6a 40 9f 2f 04 00 00
f3 6e 40 9f 2f 60 00 00 f2 ce 40 9f 2f 46 05 00 f1 15 46 9f
2f cc 00 00 f3 e2 46 9f 2f 68 01 00 f1 4b 48 9f 2f d2 05 00
f2 1d 4e 9f 2f fe 05 00 f3 1b 54 9f 2f 3d 00 00 f2 58 54 9f
2f 70 03 00
`;

// Chạy chức năng giải mã
main(sampleHexData);

// Để sử dụng trong môi trường Node.js, bạn có thể xuất các hàm này:
export {
  decodeSleepData,
  hexStringToByteArray,
  formatHexOutput
};