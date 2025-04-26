/*
* Script debug Frida để theo dõi các phương thức liên quan đến:
* 1. Lưu dữ liệu giấc ngủ vào database sau unpack
* 2. Kiểm tra múi giờ
* 3. Theo dõi quá trình unpack dữ liệu hex
* 4. Chặn xóa dữ liệu nhẫn
*/

// Lưu trữ log vào bộ nhớ để có thể xuất ra sau này nếu cần
var logHistory = [];

// Hàm để ghi log
function log(message) {
    // Lấy thời gian hiện tại
    var currentDate = new Date();
    var timestamp = currentDate.toLocaleString();
    
    // Tạo nội dung log với timestamp
    var logEntry = "[" + timestamp + "] " + message;
    
    // Lưu vào bộ nhớ
    logHistory.push(logEntry);
    
    // Hiển thị trên console
    console.log(logEntry);
}

// Hàm hỗ trợ chuyển đổi mảng byte thành chuỗi hex dễ đọc
function bytesToHex(bytes) {
    let hex = '';
    let chunks = [];
    let idx = 0;
    const LINE_LEN = 24; // Số byte trên mỗi dòng
    
    for (let i = 0; i < bytes.length; i++) {
        let byte = bytes[i] & 0xFF;
        let hexByte = ('0' + byte.toString(16)).slice(-2);
        hex += hexByte + ' ';
        
        // Tạo định dạng giống như yêu cầu (nhiều dòng, mỗi dòng 20 byte)
        if ((i + 1) % LINE_LEN === 0 || i === bytes.length - 1) {
            chunks.push(hex.trim());
            hex = '';
        }
    }
    
    return chunks.join('\n                        ');
}

Java.perform(function() {
    console.log("[+] Script started - Debug dữ liệu giấc ngủ và múi giờ");

    console.log("[+] Script started - Debug dữ liệu giấc ngủ và múi giờ");
    console.log("[+] Đã thiết lập ghi log vào bộ nhớ");

    // ===== HOOK CHẶN XÓA DỮ LIỆU NHẪN =====
    
    try {
        var YCBTClient = Java.use("com.yucheng.ycbtsdk.YCBTClient");

        // Hook phương thức xóa dữ liệu sau khi đã đồng bộ
        if (YCBTClient.deleteHealthHistoryData) {
            YCBTClient.deleteHealthHistoryData.overload('int', 'com.yucheng.ycbtsdk.response.BleDataResponse').implementation = function (type, response) {
                console.log("\n[+] YCBTClient.deleteHealthHistoryData() được gọi");
                console.log("    └─ Tham số đầu vào: type = " + type);

                // Kiểm tra nếu là yêu cầu xóa dữ liệu giấc ngủ (type = 4)
                if (type === 4) {
                    console.log("    └─ ĐÃ CHẶN XÓA DỮ LIỆU GIẤC NGỦ!");
                    // Gọi phương thức gốc với một loại dữ liệu không tồn tại để tránh xóa
                    this.deleteHealthHistoryData(9999, response);
                    return;
                }
                
                // Kiểm tra nếu là yêu cầu xóa dữ liệu nhẫn (type từ 1344 đến 1348)
                if (type >= 1344 && type <= 1348) {
                    console.log("    └─ ĐÃ CHẶN XÓA DỮ LIỆU NHẪN (type = " + type + ")!");
                    // Gọi phương thức gốc với một loại dữ liệu không tồn tại để tránh xóa
                    this.deleteHealthHistoryData(9999, response);
                    return;
                }

                // Gọi phương thức gốc và KHÔNG trả về gì (vì kiểu trả về là void)
                this.deleteHealthHistoryData(type, response);
                console.log("    └─ Đã gọi phương thức xóa dữ liệu");
                return;
            };
            console.log("[+] Đã hook YCBTClient.deleteHealthHistoryData() - CHẶN XÓA DỮ LIỆU NHẪN");
        }

        // Hook phương thức yêu cầu dữ liệu giấc ngủ
        if (YCBTClient.healthHistorySync) {
            YCBTClient.healthHistorySync.overload('int', 'com.yucheng.ycbtsdk.response.BleDataResponse').implementation = function (type, response) {
                console.log("\n[+] YCBTClient.healthHistorySync() được gọi");
                console.log("    └─ Tham số đầu vào: type = " + type);

                var result = this.healthHistorySync(type, response);
                console.log("    └─ Kết quả trả về: " + result);
                return result;
            };
            console.log("[+] Đã hook YCBTClient.healthHistorySync()");
        }
    } catch (e) {
        console.log("[-] Lỗi khi hook YCBTClient: " + e);
    }
    
    // ===== HOOK CÁC PHƯƠNG THỨC LƯU DỮ LIỆU GIẤC NGỦ =====
    
    // 1. Hook SleepDbUtils - insertMsgModel và insertMultMsgModel
    var SleepDbUtils = Java.use("com.yucheng.smarthealthpro.greendao.utils.SleepDbUtils");
    
    // Hook phương thức insertMsgModel
    SleepDbUtils.insertMsgModel.implementation = function(sleepDb) {
        console.log("[+] SleepDbUtils.insertMsgModel() được gọi");
        
        if (sleepDb !== null) {
            try {
                console.log("    - SleepDb Info:");
                console.log("      + StartTime: " + sleepDb.getStartTime());
                console.log("      + EndTime: " + sleepDb.getEndTime());
                console.log("      + DeepSleepTotal: " + sleepDb.getDeepSleepTotal());
                console.log("      + LightSleepTotal: " + sleepDb.getLightSleepTotal());
                console.log("      + TimeYearToDate: " + sleepDb.timeYearToDate.value);
                console.log("      + UserId: " + sleepDb.userId.value);
                console.log("      + IsUpload: " + sleepDb.isUpload.value);
                
                // Thêm các thuộc tính khác nếu cần
            } catch (e) {
                console.log("    - Error accessing SleepDb properties: " + e);
            }
        } else {
            console.log("    - SleepDb is null");
        }
        
        var result = this.insertMsgModel(sleepDb);
        console.log("    - Result: " + result);
        return result;
    };

    // Hook phương thức insertMultMsgModel
    SleepDbUtils.insertMultMsgModel.implementation = function(list) {
        console.log("[+] SleepDbUtils.insertMultMsgModel() được gọi");
        
        if (list !== null) {
            console.log("    - List size: " + list.size());
            
            // In thông tin của vài phần tử đầu tiên trong danh sách
            try {
                var size = list.size();
                var maxDisplay = Math.min(3, size); // Hiển thị tối đa 3 phần tử để tránh log quá dài
                
                for (var i = 0; i < maxDisplay; i++) {
                    var sleepDb = list.get(i);
                    console.log("    - SleepDb[" + i + "] Info:");
                    console.log("      + StartTime: " + sleepDb.getStartTime());
                    console.log("      + EndTime: " + sleepDb.getEndTime());
                    console.log("      + DeepSleepTotal: " + sleepDb.getDeepSleepTotal());
                    console.log("      + LightSleepTotal: " + sleepDb.getLightSleepTotal());
                    console.log("      + TimeYearToDate: " + sleepDb.timeYearToDate.value);
                }
                
                if (size > maxDisplay) {
                    console.log("    - ... and " + (size - maxDisplay) + " more items");
                }
            } catch (e) {
                console.log("    - Error accessing list properties: " + e);
            }
        } else {
            console.log("    - List is null");
        }
        
        var result = this.insertMultMsgModel(list);
        console.log("    - Result: " + result);
        return result;
    };
    
    // 2. Hook tất cả các phương thức unpack trong DataUnpack
    try {
        var DataUnpack = Java.use("com.yucheng.ycbtsdk.core.DataUnpack");
        
        // Tìm và hook tất cả các phương thức unpack
        var methods = DataUnpack.class.getDeclaredMethods();
        console.log("[+] Đang hook tất cả các phương thức unpack trong DataUnpack");
        
        for (var i = 0; i < methods.length; i++) {
            var methodName = methods[i].getName();
            if (methodName.startsWith("unpack")) {
                console.log("[*] Phát hiện phương thức unpack: " + methodName);
                
                // Hook động tất cả các phương thức unpack
                try {
                    (function(m_name) {
                        var originalMethod = DataUnpack[m_name];
                        if (originalMethod) {
                            DataUnpack[m_name].implementation = function() {
                                console.log("\n[+] DataUnpack." + m_name + "() được gọi");
                                
                                // In ra dữ liệu đầu vào dưới dạng hex nếu là array byte
                                if (arguments[0] !== null && arguments[0] instanceof Array) {
                                    var bArr = arguments[0];
                                    console.log("    - Input length: " + bArr.length);
                                    
                                    if (bArr.length >= 20) {
                                        // In dữ liệu hex theo định dạng đẹp
                                        console.log("    - Input data:\n                        " + bytesToHex(bArr));
                                        
                                        // Nếu độ dài gần đúng với yêu cầu (khoảng 424 byte)
                                        if (bArr.length >= 400 && bArr.length <= 500) {
                                            console.log("    - !!! PHÁT HIỆN DỮ LIỆU QUAN TRỌNG !!! Độ dài gần với yêu cầu (424 byte)");
                                        }
                                    } else {
                                        // Đối với mảng nhỏ, chỉ hiển thị trên một dòng
                                        var inputHex = "";
                                        for (var i = 0; i < bArr.length; i++) {
                                            inputHex += ('0' + (bArr[i] & 0xFF).toString(16)).slice(-2) + " ";
                                        }
                                        console.log("    - Input data: " + inputHex);
                                    }
                                }
                                
                                // Gọi phương thức gốc
                                var result = originalMethod.apply(this, arguments);
                                
                                try {
                                    if (result !== null && typeof result === 'object') {
                                        // In loại dữ liệu được trả về
                                        console.log("    - Result type: " + (result.getClass ? result.getClass().getName() : typeof result));
                                        
                                        // Nếu là HashMap, thử in các key
                                        if (result.keySet) {
                                            var keys = result.keySet().toArray();
                                            console.log("    - Result keys: " + keys);
                                            
                                            // In các giá trị cho một số key quan trọng
                                            for (var i = 0; i < keys.length; i++) {
                                                var key = keys[i];
                                                if (key && (String(key).includes("sleep") || 
                                                          String(key).includes("time") || 
                                                          String(key).includes("deep") || 
                                                          String(key).includes("light"))) {
                                                    var value = result.get(key);
                                                    console.log("    - " + key + ": " + value);
                                                }
                                            }
                                        }
                                    }
                                } catch (ex) {
                                    console.log("    - Error analyzing result: " + ex);
                                }
                                
                                return result;
                            };
                        }
                    })(methodName);
                } catch (hookErr) {
                    console.log("    - Error hooking method " + methodName + ": " + hookErr);
                }
            }
        }
        
        // Hook đặc biệt cho các phương thức cụ thể liên quan đến sleep nếu có
        if (DataUnpack.unpackSleepData) {
            console.log("[*] Phát hiện phương thức unpackSleepData, thêm hook đặc biệt");
        }
        
    } catch (e) {
        console.log("[-] Error hooking DataUnpack: " + e);
    }
    
    // ===== HOOK CÁC PHƯƠNG THỨC KIỂM TRA MÚI GIỜ =====
    
    // Hook TimeZoneUtils
    try {
        var TimeZoneUtils = Java.use("com.yucheng.smarthealthpro.utils.TimeZoneUtils");
        
        TimeZoneUtils.getTimeZone.implementation = function() {
            console.log("[+] TimeZoneUtils.getTimeZone() được gọi");
            var result = this.getTimeZone();
            console.log("    - Result: " + result);
            return result;
        };
        
        TimeZoneUtils.getTimeZoneOffset.implementation = function() {
            console.log("[+] TimeZoneUtils.getTimeZoneOffset() được gọi");
            var result = this.getTimeZoneOffset();
            console.log("    - Result: " + result);
            return result;
        };
    } catch (e) {
        console.log("[-] Error hooking TimeZoneUtils: " + e);
    }
    
    // ===== HOOK THÊM CÁC LỚP VÀ PHƯƠNG THỨC KHÁC =====
    
    // HOOK TimeUtil nếu có
    try {
        var TimeUtil = Java.use("com.yucheng.smarthealthpro.utils.TimeUtil");
        var timeMethods = TimeUtil.class.getDeclaredMethods();
        
        for (var i = 0; i < timeMethods.length; i++) {
            var methodName = timeMethods[i].getName();
            console.log("[*] Phát hiện phương thức TimeUtil: " + methodName);
        }
    } catch (e) {
        console.log("[-] Error accessing TimeUtil methods: " + e);
    }
    
    // HOOK YCBTClientImpl - các phương thức tải dữ liệu giấc ngủ
    try {
        var YCBTClientImpl = Java.use("com.yucheng.ycbtsdk.YCBTClientImpl");
        
        // Hook phương thức tải dữ liệu (nếu có)
        if (YCBTClientImpl.getSleepHistoryData) {
            YCBTClientImpl.getSleepHistoryData.implementation = function() {
                console.log("[+] YCBTClientImpl.getSleepHistoryData() được gọi");
                var result = this.getSleepHistoryData();
                console.log("    - Result: " + JSON.stringify(result));
                return result;
            };
        }
    } catch (e) {
        console.log("[-] Error hooking YCBTClientImpl: " + e);
    }
    
    // Hook class SleepDb để theo dõi dữ liệu được lưu
    try {
        var SleepDb = Java.use("com.yucheng.smarthealthpro.greendao.bean.SleepDb");
        
        // Hook constructor nếu có nhiều constructor
        SleepDb.$init.overloads.forEach(function(overload) {
            overload.implementation = function() {
                console.log("[+] SleepDb constructor được gọi với " + arguments.length + " tham số");
                
                // Gọi constructor gốc
                var result = overload.apply(this, arguments);
                
                // Log thông tin
                try {
                    if (arguments.length > 0) {
                        console.log("    - Constructor params: " + JSON.stringify(arguments));
                    }
                } catch (e) {
                    console.log("    - Error logging constructor params: " + e);
                }
                
                return result;
            };
        });
    } catch (e) {
        console.log("[-] Error hooking SleepDb: " + e);
    }
    
    // ===== HOOK CÁC LỚP QUAN TRỌNG KHÁC =====
    
    // Hook YCBTClient để theo dõi các phương thức xử lý dữ liệu từ nhẫn
    try {
        var YCBTClient = Java.use("com.yucheng.ycbtsdk.YCBTClient");
        
        // Tìm và hook tất cả các phương thức liên quan đến sleep
        var ycbtMethods = YCBTClient.class.getDeclaredMethods();
        for (var i = 0; i < ycbtMethods.length; i++) {
            var methodName = ycbtMethods[i].getName();
            if (methodName.toLowerCase().includes("sleep") || 
                methodName.toLowerCase().includes("health") || 
                methodName.toLowerCase().includes("history") || 
                methodName.toLowerCase().includes("data")) {
                console.log("[*] Phát hiện phương thức YCBTClient có thể liên quan: " + methodName);
                
                // Hook phương thức
                try {
                    (function(m_name) {
                        if (YCBTClient[m_name]) {
                            var originalMethod = YCBTClient[m_name];
                            YCBTClient[m_name].implementation = function() {
                                console.log("[+] YCBTClient." + m_name + "() được gọi với " + arguments.length + " tham số");
                                
                                // In ra các tham số quan trọng
                                for (var i = 0; i < arguments.length; i++) {
                                    try {
                                        if (arguments[i] !== null) {
                                            if (arguments[i] instanceof Array) {
                                                // Nếu là mảng byte, hiển thị định dạng hex
                                                if (arguments[i].length > 0 && typeof arguments[i][0] === 'number') {
                                                    console.log("    - Param[" + i + "] (byte[]): " + bytesToHex(arguments[i]));
                                                } else {
                                                    console.log("    - Param[" + i + "] (array): " + arguments[i]);
                                                }
                                            } else {
                                                console.log("    - Param[" + i + "]: " + arguments[i]);
                                            }
                                        }
                                    } catch (ex) {
                                        console.log("    - Error accessing param " + i + ": " + ex);
                                    }
                                }
                                
                                var result = originalMethod.apply(this, arguments);
                                console.log("    - Result: " + result);
                                return result;
                            };
                        }
                    })(methodName);
                } catch (hookErr) {
                    console.log("    - Error hooking YCBTClient method " + methodName + ": " + hookErr);
                }
            }
        }
    } catch (e) {
        console.log("[-] Error hooking YCBTClient: " + e);
    }
    
    // Hook các phương thức xóa dữ liệu lịch sử
    try {
        var healthMethods = ["deleteHealthHistoryData", "deleteHealthDataFromDB", "deleteHealthData"];
        
        for (var i = 0; i < healthMethods.length; i++) {
            var methodName = healthMethods[i];
            try {
                // Thử tìm lớp chứa phương thức
                var classes = ["com.yucheng.ycbtsdk.YCBTClient", "com.yucheng.ycbtsdk.YCBTClientImpl", 
                              "com.yucheng.smarthealthpro.greendao.utils.SleepDbUtils"];
                
                for (var j = 0; j < classes.length; j++) {
                    try {
                        var cls = Java.use(classes[j]);
                        if (cls && cls[methodName]) {
                            console.log("[*] Phát hiện và hook phương thức xóa dữ liệu: " + classes[j] + "." + methodName);
                            
                            cls[methodName].implementation = function() {
                                console.log("[!] PHƯƠNG THỨC XÓA DỮ LIỆU được gọi: " + this.$className + "." + methodName);
                                console.log("    - Tham số: " + JSON.stringify(arguments));
                                
                                // Ghi log stack trace để biết ai gọi phương thức này
                                try {
                                    var exception = Java.use('java.lang.Exception').$new('Stacktrace');
                                    var stackStr = exception.getStackTrace().toString();
                                    console.log("    - Stack trace: " + stackStr);
                                } catch (err) {
                                    console.log("    - Không thể lấy stack trace: " + err);
                                }
                                
                                // Gọi phương thức gốc và trả về kết quả
                                var result = this[methodName].apply(this, arguments);
                                console.log("    - Result: " + result);
                                return result;
                            };
                        }
                    } catch (classErr) {
                        // Bỏ qua lỗi khi tìm lớp
                    }
                }
            } catch (methodErr) {
                console.log("    - Error hooking delete method " + methodName + ": " + methodErr);
            }
        }
    } catch (e) {
        console.log("[-] Error setting up delete method hooks: " + e);
    }
    
    // Hàm hỗ trợ để chuyển đổi đối tượng Java thành chuỗi JSON an toàn
    function safeJsonStringify(obj) {
        try {
            if (obj === null || obj === undefined) {
                return "null";
            }
            
            // Nếu là đối tượng Java, thử chuyển thành đối tượng JS
            var jsObj = {};
            
            try {
                // Thử lấy các trường trong đối tượng Java
                if (obj.getClass && obj.getClass().getDeclaredFields) {
                    var fields = obj.getClass().getDeclaredFields();
                    for (var i = 0; i < fields.length; i++) {
                        var field = fields[i];
                        field.setAccessible(true);
                        try {
                            var fieldName = field.getName();
                            var fieldValue = field.get(obj);
                            jsObj[fieldName] = fieldValue;
                        } catch (fieldErr) {
                            // Bỏ qua nếu không lấy được trường
                        }
                    }
                    
                    return JSON.stringify(jsObj);
                }
            } catch (err) {
                // Bỏ qua nếu không phải đối tượng Java
            }
            
            // Thử chuyển đổi trực tiếp
            return JSON.stringify(obj);
        } catch (e) {
            // Nếu không chuyển được thành JSON, trả về chuỗi mô tả
            return "[Không thể chuyển thành JSON: " + e.message + "]";
        }
    }
    
    // Hàm trợ giúp để lấy mô tả loại giấc ngủ dựa trên mã
    function getSleepTypeString(sleepType) {
        switch (sleepType) {
            case 241:
                return "Ngủ sâu";
            case 242:
                return "Ngủ nhẹ";
            case 243:
                return "REM";
            case 244:
                return "Thức giấc";
            case -1:
                return "Không xác định";
            default:
                return "Không rõ (" + sleepType + ")";
        }
    }
    
    // Hàm xuất log ra console để copy/paste
    function exportLogToConsole() {
        try {
            console.log("\n\n=================== BẮT ĐẦU LOG ===================\n");
            
            // Hiển thị tất cả log đã lưu trữ
            for (var i = 0; i < logHistory.length; i++) {
                console.log(logHistory[i]);
            }
            
            console.log("\n=================== KẾT THÚC LOG ===================\n");
            console.log("[✓] Đã xuất " + logHistory.length + " dòng log ra console");
            console.log("[✓] Hãy copy/paste toàn bộ log vào file văn bản để lưu trữ");
            
            return true;
        } catch (e) {
            console.log("[!] Lỗi khi xuất log: " + e.message);
            return false;
        }
    }
    
    // Hàm xuất log ra file trên Android
    function exportLogToAndroid() {
        try {
            // Đường dẫn đến file log
            var logFilePath = "/sdcard/sleep_debug_log.txt";
            
            // Sử dụng Java FileWriter
            var FileWriter = Java.use("java.io.FileWriter");
            var writer = FileWriter.$new(logFilePath, false); // false = ghi đè, không append
            
            // Ghi tất cả log vào file
            for (var i = 0; i < logHistory.length; i++) {
                writer.write(logHistory[i] + "\n");
            }
            
            // Đóng file
            writer.close();
            
            console.log("[✓] Đã xuất " + logHistory.length + " dòng log ra file: " + logFilePath);
            return true;
        } catch (e) {
            console.log("[!] Lỗi khi xuất log ra Android: " + e.message);
            return false;
        }
    }
    
    // Tạo các hàm global để xuất log
    global.exportLogs = function() {
        exportLogToConsole();
    };
    
    global.saveLogToAndroid = function() {
        exportLogToAndroid();
    };
    
    console.log("[+] Script hook đã hoàn tất, đang chờ các cuộc gọi hàm...");
    console.log("[i] Script sẽ theo dõi: ");
    console.log("    1. Tất cả các phương thức unpack của DataUnpack");
    console.log("    2. Các phương thức lưu SleepDb vào database");
    console.log("    3. Các phương thức kiểm tra và xử lý múi giờ");
    console.log("    4. Các phương thức xóa dữ liệu liên quan đến sức khỏe");
    console.log("[+] Để xuất log ra console, gọi: exportLogs()");
    console.log("[+] Để lưu log vào file trên Android, gọi: saveLogToAndroid()");
});
