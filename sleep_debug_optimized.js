/*
* Script debug Frida để theo dõi các phương thức liên quan đến:
* 1. Lưu dữ liệu giấc ngủ vào database sau unpack
* 2. Kiểm tra múi giờ
* 3. Theo dõi quá trình unpack dữ liệu hex
* 4. Chặn xóa dữ liệu nhẫn
*/

// Lưu trữ log vào bộ nhớ để có thể xuất ra sau này
var logHistory = [];

// Hàm để ghi log
function log(message) {
    var currentDate = new Date();
    var timestamp = currentDate.toLocaleString();
    var logEntry = "[" + timestamp + "] " + message;
    logHistory.push(logEntry);
    console.log(logEntry);
}

// Hàm chuyển đổi mảng byte thành chuỗi hex theo định dạng yêu cầu
function bytesToHex(bytes) {
    let hex = '';
    let chunks = [];
    const LINE_LEN = 20; // Số byte trên mỗi dòng
    
    for (let i = 0; i < bytes.length; i++) {
        let byte = bytes[i] & 0xFF;
        let hexByte = ('0' + byte.toString(16)).slice(-2);
        hex += hexByte + ' ';
        
        if ((i + 1) % LINE_LEN === 0 || i === bytes.length - 1) {
            chunks.push(hex.trim());
            hex = '';
        }
    }
    
    return chunks.join('\n                        ');
}

// Hàm chuyển đối tượng Java thành JSON an toàn
function safeJsonStringify(obj) {
    try {
        if (obj === null || obj === undefined) return "null";
        
        // Xử lý đối tượng Java
        var jsObj = {};
        try {
            if (obj.getClass && obj.getClass().getDeclaredFields) {
                var fields = obj.getClass().getDeclaredFields();
                for (var i = 0; i < fields.length; i++) {
                    var field = fields[i];
                    field.setAccessible(true);
                    try {
                        var fieldName = field.getName();
                        var fieldValue = field.get(obj);
                        jsObj[fieldName] = fieldValue;
                    } catch (e) { /* bỏ qua lỗi truy cập trường */ }
                }
                return JSON.stringify(jsObj);
            }
        } catch (e) { /* bỏ qua nếu không phải đối tượng Java */ }
        
        // Thử JSON.stringify trực tiếp
        return JSON.stringify(obj);
    } catch (e) {
        return "[Không thể chuyển thành JSON: " + e.message + "]";
    }
}

// Hàm lấy mô tả loại giấc ngủ dựa trên mã
function getSleepTypeString(sleepType) {
    switch (sleepType) {
        case 241: return "Ngủ sâu";
        case 242: return "Ngủ nhẹ";
        case 243: return "REM";
        case 244: return "Thức giấc";
        case -1: return "Không xác định";
        default: return "Không rõ (" + sleepType + ")";
    }
}

Java.perform(function() {
    log("Bắt đầu script debug dữ liệu giấc ngủ");
    
    // ===== 1. CHẶN XÓA DỮ LIỆU NHẪN =====
    try {
        var YCBTClient = Java.use("com.yucheng.ycbtsdk.YCBTClient");
        
        // Hook phương thức xóa dữ liệu
        if (YCBTClient.deleteHealthHistoryData) {
            YCBTClient.deleteHealthHistoryData.overload('int', 'com.yucheng.ycbtsdk.response.BleDataResponse').implementation = function(type, response) {
                log("YCBTClient.deleteHealthHistoryData() được gọi với type = " + type);
                
                // Chặn xóa dữ liệu giấc ngủ (type = 4)
                if (type === 4) {
                    log("⚠️ ĐÃ CHẶN XÓA DỮ LIỆU GIẤC NGỦ!");
                    this.deleteHealthHistoryData(9999, response); // Sử dụng type không tồn tại
                    return;
                }
                
                // Chặn xóa dữ liệu nhẫn (type từ 1344 đến 1348)
                if (type >= 1344 && type <= 1348) {
                    log("⚠️ ĐÃ CHẶN XÓA DỮ LIỆU NHẪN (type = " + type + ")!");
                    this.deleteHealthHistoryData(9999, response); // Sử dụng type không tồn tại
                    return;
                }
                
                // Gọi phương thức gốc nếu không phải dữ liệu cần chặn
                this.deleteHealthHistoryData(type, response);
                log("Đã xóa dữ liệu loại: " + type);
            };
            log("✓ Đã hook phương thức deleteHealthHistoryData - CHẶN XÓA DỮ LIỆU NHẪN");
        }
        
        // Hook phương thức đồng bộ dữ liệu
        if (YCBTClient.healthHistorySync) {
            YCBTClient.healthHistorySync.overload('int', 'com.yucheng.ycbtsdk.response.BleDataResponse').implementation = function(type, response) {
                log("YCBTClient.healthHistorySync() được gọi với type = " + type);
                var result = this.healthHistorySync(type, response);
                log("Kết quả đồng bộ: " + result);
                return result;
            };
            log("✓ Đã hook phương thức healthHistorySync");
        }
        
        // Hook phương thức lấy dữ liệu lịch sử sức khỏe
        if (YCBTClient.healthHistoryData) {
            try {
                YCBTClient.healthHistoryData.overload('int', 'com.yucheng.ycbtsdk.response.BleDataResponse').implementation = function(type, response) {
                    log("YCBTClient.healthHistoryData() được gọi với type = " + type);
                    
                    // Gọi phương thức gốc
                    this.healthHistoryData(type, response);
                    log("Đã gọi lấy dữ liệu lịch sử sức khỏe loại: " + type);
                };
                log("✓ Đã hook phương thức healthHistoryData");
            } catch (e) {
                log("Lỗi khi hook healthHistoryData: " + e);
            }
        }
    } catch (e) {
        log("Lỗi khi hook YCBTClient: " + e);
    }
    
    // ===== 2. HOOK DATA UNPACK - CHỈ CÁC PHƯƠNG THỨC LIÊN QUAN ĐẾN GIẤC NGỦ =====
    try {
        var DataUnpack = Java.use("com.yucheng.ycbtsdk.core.DataUnpack");
        
        // Danh sách các phương thức unpack cần theo dõi
        var targetMethods = [
            "unpackHealthData",
            "unpackSleepData",
            "unpackGetSleepStatus"
        ];
        
        // Hook các phương thức đã chọn
        for (var i = 0; i < targetMethods.length; i++) {
            var methodName = targetMethods[i];
            try {
                if (DataUnpack[methodName]) {
                    (function(m_name) {
                        var originalMethod = DataUnpack[m_name];
                        DataUnpack[m_name].implementation = function() {
                            log("DataUnpack." + m_name + "() được gọi");
                            
                            // In ra dữ liệu đầu vào nếu là mảng byte
                            if (arguments[0] !== null && arguments[0] instanceof Array) {
                                var bArr = arguments[0];
                                log("Input length: " + bArr.length);
                                
                                // Nếu dữ liệu đủ lớn, hiển thị chi tiết
                                if (bArr.length > 10) {
                                    log("Input data:\n                        " + bytesToHex(bArr));
                                    
                                    // Nếu độ dài gần với yêu cầu (khoảng 424 byte)
                                    if (bArr.length >= 400 && bArr.length <= 450) {
                                        log("⚠️ PHÁT HIỆN DỮ LIỆU QUAN TRỌNG! Độ dài gần với yêu cầu (424 byte)");
                                    }
                                } else {
                                    // Đối với mảng nhỏ, hiển thị trên một dòng
                                    var shortHex = "";
                                    for (var i = 0; i < bArr.length; i++) {
                                        shortHex += ('0' + (bArr[i] & 0xFF).toString(16)).slice(-2) + " ";
                                    }
                                    log("Input data: " + shortHex);
                                }
                            }
                            
                            // Gọi phương thức gốc
                            var result = originalMethod.apply(this, arguments);
                            
                            // Phân tích kết quả
                            try {
                                if (result !== null && typeof result === 'object') {
                                    log("Result type: " + (result.getClass ? result.getClass().getName() : typeof result));
                                    
                                    // Nếu kết quả là HashMap, phân tích các key
                                    if (result.keySet) {
                                        var keys = result.keySet().toArray();
                                        log("Result keys: " + keys);
                                        
                                        // In chi tiết các key liên quan đến dữ liệu giấc ngủ
                                        for (var i = 0; i < keys.length; i++) {
                                            var key = keys[i];
                                            if (key && (String(key).includes("sleep") || 
                                                       String(key).includes("time") || 
                                                       String(key).includes("deep") || 
                                                       String(key).includes("light"))) {
                                                var value = result.get(key);
                                                log(key + ": " + value);
                                            }
                                        }
                                    }
                                }
                            } catch (ex) {
                                log("Lỗi khi phân tích kết quả: " + ex);
                            }
                            
                            return result;
                        };
                        log("✓ Đã hook " + m_name + "()");
                    })(methodName);
                } else {
                    log("Không tìm thấy phương thức: " + methodName);
                }
            } catch (hookErr) {
                log("Lỗi khi hook phương thức " + methodName + ": " + hookErr);
            }
        }
    } catch (e) {
        log("Lỗi khi hook DataUnpack: " + e);
    }
    
    // ===== 3. HOOK LƯU DỮ LIỆU VÀO DATABASE =====
    try {
        var SleepDbUtils = Java.use("com.yucheng.smarthealthpro.greendao.utils.SleepDbUtils");
        
        // Hook phương thức lưu một bản ghi
        SleepDbUtils.insertMsgModel.implementation = function(sleepDb) {
            log("SleepDbUtils.insertMsgModel() được gọi");
            
            if (sleepDb !== null) {
                try {
                    log("Thông tin SleepDb:");
                    log("  StartTime: " + sleepDb.getStartTime());
                    log("  EndTime: " + sleepDb.getEndTime());
                    log("  DeepSleepTotal: " + sleepDb.getDeepSleepTotal());
                    log("  LightSleepTotal: " + sleepDb.getLightSleepTotal());
                    
                    // Thử truy cập các trường khác
                    try { log("  TimeYearToDate: " + sleepDb.timeYearToDate.value); } catch (e) {}
                    try { log("  UserId: " + sleepDb.userId.value); } catch (e) {}
                    try { log("  IsUpload: " + sleepDb.isUpload.value); } catch (e) {}
                    try { log("  RapidEyeMovementTotal: " + sleepDb.rapidEyeMovementTotal.value); } catch (e) {}
                    try { log("  WakeCount: " + sleepDb.wakeCount.value); } catch (e) {}
                } catch (e) {
                    log("Lỗi truy cập thuộc tính SleepDb: " + e);
                }
            } else {
                log("SleepDb là null");
            }
            
            var result = this.insertMsgModel(sleepDb);
            log("Kết quả lưu: " + result);
            return result;
        };
        log("✓ Đã hook phương thức insertMsgModel");
        
        // Hook phương thức lưu nhiều bản ghi
        SleepDbUtils.insertMultMsgModel.implementation = function(list) {
            log("SleepDbUtils.insertMultMsgModel() được gọi");
            
            if (list !== null) {
                try {
                    var size = list.size();
                    log("Số lượng bản ghi: " + size);
                    
                    // Hiển thị thông tin của một số bản ghi đầu tiên
                    var maxDisplay = Math.min(2, size);
                    for (var i = 0; i < maxDisplay; i++) {
                        var sleepDb = list.get(i);
                        log("SleepDb[" + i + "]:");
                        log("  StartTime: " + sleepDb.getStartTime());
                        log("  EndTime: " + sleepDb.getEndTime());
                        log("  DeepSleepTotal: " + sleepDb.getDeepSleepTotal());
                        log("  LightSleepTotal: " + sleepDb.getLightSleepTotal());
                    }
                    
                    if (size > maxDisplay) {
                        log("... và " + (size - maxDisplay) + " bản ghi khác");
                    }
                } catch (e) {
                    log("Lỗi truy cập danh sách: " + e);
                }
            } else {
                log("Danh sách là null");
            }
            
            var result = this.insertMultMsgModel(list);
            log("Kết quả lưu: " + result);
            return result;
        };
        log("✓ Đã hook phương thức insertMultMsgModel");
    } catch (e) {
        log("Lỗi khi hook SleepDbUtils: " + e);
    }
    
    // ===== 4. HOOK MÚI GIỜ VÀ TIMESTAMP =====
    try {
        var TimeZoneUtils = Java.use("com.yucheng.smarthealthpro.utils.TimeZoneUtils");
        
        // Hook phương thức lấy múi giờ
        TimeZoneUtils.getTimeZone.implementation = function() {
            log("TimeZoneUtils.getTimeZone() được gọi");
            var result = this.getTimeZone();
            log("Múi giờ: " + result);
            return result;
        };
        
        // Hook phương thức lấy offset múi giờ
        TimeZoneUtils.getTimeZoneOffset.implementation = function() {
            log("TimeZoneUtils.getTimeZoneOffset() được gọi");
            var result = this.getTimeZoneOffset();
            log("Offset múi giờ: " + result);
            return result;
        };
        log("✓ Đã hook các phương thức múi giờ");
    } catch (e) {
        log("Lỗi khi hook TimeZoneUtils: " + e);
    }
    
    // Thử hook TimeStampUtils nếu có
    try {
        var TimeStampUtils = Java.use("com.yucheng.smarthealthpro.utils.TimeStampUtils");
        
        // Lấy danh sách các phương thức
        var methods = TimeStampUtils.class.getDeclaredMethods();
        for (var i = 0; i < methods.length; i++) {
            var methodName = methods[i].getName();
            try {
                if (methodName.toLowerCase().includes("time") || 
                    methodName.toLowerCase().includes("stamp") || 
                    methodName.toLowerCase().includes("date")) {
                    
                    (function(m_name) {
                        if (TimeStampUtils[m_name]) {
                            var originalMethod = TimeStampUtils[m_name];
                            
                            // Hook phương thức
                            TimeStampUtils[m_name].implementation = function() {
                                log("TimeStampUtils." + m_name + "() được gọi");
                                
                                // In ra các tham số
                                var params = [];
                                for (var i = 0; i < arguments.length; i++) {
                                    params.push(String(arguments[i]));
                                }
                                if (params.length > 0) {
                                    log("Tham số: " + params.join(", "));
                                }
                                
                                // Gọi phương thức gốc
                                var result = originalMethod.apply(this, arguments);
                                log("Kết quả: " + result);
                                return result;
                            };
                            log("✓ Đã hook TimeStampUtils." + m_name + "()");
                        }
                    })(methodName);
                }
            } catch (hookErr) {
                // Bỏ qua lỗi khi hook từng phương thức
            }
        }
    } catch (e) {
        log("Lỗi khi hook TimeStampUtils: " + e);
    }
    
    // ===== 5. CÔNG CỤ XUẤT LOG =====
    
    // Xuất log ra console
    global.exportLogs = function() {
        console.log("\n=================== BẮT ĐẦU LOG ===================\n");
        
        for (var i = 0; i < logHistory.length; i++) {
            console.log(logHistory[i]);
        }
        
        console.log("\n=================== KẾT THÚC LOG ===================\n");
        console.log("[✓] Đã xuất " + logHistory.length + " dòng log");
    };
    
    // Lưu log vào file trên Android
    global.saveLogToAndroid = function() {
        try {
            var logFilePath = "/sdcard/sleep_debug_log.txt";
            var FileWriter = Java.use("java.io.FileWriter");
            var writer = FileWriter.$new(logFilePath, false);
            
            for (var i = 0; i < logHistory.length; i++) {
                writer.write(logHistory[i] + "\n");
            }
            
            writer.close();
            console.log("[✓] Đã lưu log vào file: " + logFilePath);
            return true;
        } catch (e) {
            console.log("[!] Lỗi khi lưu log: " + e.message);
            return false;
        }
    };
    
    log("Script đã sẵn sàng theo dõi:");
    log("1. Dữ liệu giấc ngủ được unpack từ nhẫn");
    log("2. Cách dữ liệu được lưu vào database");
    log("3. Cách xử lý múi giờ và timestamp");
    log("4. Đã chặn xóa dữ liệu nhẫn");
    log("Sử dụng 'exportLogs()' để xuất log, 'saveLogToAndroid()' để lưu vào file");
});
