Java.perform(function() {
    console.log("[+] Script debug luồng dữ liệu giấc ngủ đã được tải");
    
    // Cấu hình log server trên PC
    var logToServer = true;
    var logServerHost = "192.168.1.101"; // Địa chỉ IP của máy tính của bạn
    var logServerPort = 8888; // Cổng log server của bạn
    
    try {
        // Khởi tạo socket kết nối đến log server
        var Socket = Java.use("java.net.Socket");
        var PrintWriter = Java.use("java.io.PrintWriter");
        var logSocket = null;
        var logWriter = null;
        
        if (logToServer) {
            try {
                logSocket = Socket.$new(logServerHost, logServerPort);
                logWriter = PrintWriter.$new(logSocket.getOutputStream(), true);
                sendLogToServer("[+] Kết nối thành công tới log server");
                sendLogToServer("============ BẮT ĐẦU PHIÊN DEBUG MỚI ============");
                console.log("[+] Đã kết nối tới log server: " + logServerHost + ":" + logServerPort);
            } catch (e) {
                console.log("[-] Lỗi kết nối tới log server: " + e.message);
                console.log("    Hãy chạy lệnh sau trên máy tính của bạn để tạo log server:");
                console.log("    nc -l -p " + logServerPort + " > sleep_debug.log");
                logToServer = false;
            }
        }
        
        // Hàm gửi log đến server
        function sendLogToServer(message) {
            if (logToServer && logWriter != null) {
                try {
                    var dateFormat = Java.use("java.text.SimpleDateFormat").$new("yyyy-MM-dd HH:mm:ss.SSS");
                    var System = Java.use("java.lang.System");
                    var timestamp = dateFormat.format(Java.use("java.util.Date").$new(System.currentTimeMillis()));
                    
                    logWriter.println("[" + timestamp + "] " + message);
                    logWriter.flush();
                } catch (e) {
                    console.log("[-] Lỗi ghi log đến server: " + e.message);
                }
            }
        }
        
        // Ghi đè hàm console.log để lưu cả vào server
        var originalLog = console.log;
        console.log = function(message) {
            originalLog(message);
            sendLogToServer(message);
        };
        
        // Đảm bảo đóng kết nối khi script kết thúc
        Process.on('exit', function() {
            try {
                if (logWriter != null) {
                    sendLogToServer("============ KẾT THÚC PHIÊN DEBUG ============");
                    logWriter.close();
                }
                if (logSocket != null) {
                    logSocket.close();
                }
                console.log("[+] Đã đóng kết nối log server");
            } catch (e) {
                console.log("[-] Lỗi khi đóng kết nối log server: " + e.message);
            }
        });
        
        try {
            // 1. DEBUG PHƯƠNG THỨC YÊU CẦU DỮ LIỆU GIẤC NGỦ TỪ THIẾT BỊ
            hookYCBTClient();
            
            // 2. DEBUG PHƯƠNG THỨC GIẢI MÃ DỮ LIỆU
            hookDataUnpack();
            
            // 3. DEBUG PHƯƠNG THỨC LƯU DỮ LIỆU VÀO CƠ SỞ DỮ LIỆU
            hookSleepDbUtils();
            
            // 4. DEBUG CÁC PHƯƠNG THỨC HIỂN THỊ DỮ LIỆU
            hookSleepActivity();
            hookSleep2Activity();
            
            // 5. DEBUG SLEEP RESPONSE
            hookSleepResponse();
            
            // 6. DEBUG BLUETOOTH GATT
            hookBluetoothGatt();
            
            console.log("[+] Đã hook thành công các phương thức liên quan đến luồng dữ liệu giấc ngủ");
        } catch (e) {
            console.log("[-] Lỗi: " + e.message);
        }
        
        // HOOK BluetoothGatt - Theo dõi dữ liệu Bluetooth
        function hookBluetoothGatt() {
            try {
                var BluetoothGatt = Java.use("android.bluetooth.BluetoothGatt");
                var BluetoothGattCharacteristic = Java.use("android.bluetooth.BluetoothGattCharacteristic");
                var BluetoothGattCallback = Java.use("android.bluetooth.BluetoothGattCallback");
                
                // Hook phương thức onCharacteristicChanged
                if (BluetoothGattCallback.onCharacteristicChanged) {
                    BluetoothGattCallback.onCharacteristicChanged.implementation = function(gatt, characteristic) {
                        console.log("\n[+] BluetoothGattCallback.onCharacteristicChanged() được gọi");
                        
                        if (characteristic != null) {
                            var uuid = characteristic.getUuid();
                            console.log("    └── UUID Characteristic: " + uuid);
                            
                            // Lấy giá trị
                            var value = characteristic.getValue();
                            if (value != null) {
                                // In ra toàn bộ giá trị hex, không giới hạn byte
                                var hexValue = "";
                                for (var i = 0; i < value.length; i++) {
                                    hexValue += (value[i] & 0xFF).toString(16).padStart(2, '0') + " ";
                                }
                                console.log("    └── Giá trị đầy đủ (hex): " + hexValue);
                                
                                // In thêm dạng ASCII nếu có thể
                                var asciiValue = "";
                                for (var i = 0; i < value.length; i++) {
                                    var charCode = value[i] & 0xFF;
                                    if (charCode >= 32 && charCode <= 126) {
                                        asciiValue += String.fromCharCode(charCode);
                                    } else {
                                        asciiValue += ".";
                                    }
                                }
                                console.log("    └── Giá trị ASCII (nếu có): " + asciiValue);
                            }
                        }
                        
                        // Gọi phương thức gốc
                        this.onCharacteristicChanged(gatt, characteristic);
                    };
                    console.log("[+] Đã hook BluetoothGattCallback.onCharacteristicChanged()");
                }
                
                // Hook phương thức onCharacteristicRead
                if (BluetoothGattCallback.onCharacteristicRead) {
                    BluetoothGattCallback.onCharacteristicRead.implementation = function(gatt, characteristic, status) {
                        console.log("\n[+] BluetoothGattCallback.onCharacteristicRead() được gọi");
                        console.log("    └── Status: " + status);
                        
                        if (characteristic != null) {
                            var uuid = characteristic.getUuid();
                            console.log("    └── UUID Characteristic: " + uuid);
                            
                            // Lấy giá trị
                            var value = characteristic.getValue();
                            if (value != null) {
                                // In ra toàn bộ giá trị hex, không giới hạn byte
                                var hexValue = "";
                                for (var i = 0; i < value.length; i++) {
                                    hexValue += (value[i] & 0xFF).toString(16).padStart(2, '0') + " ";
                                }
                                console.log("    └── Giá trị đầy đủ (hex): " + hexValue);
                            }
                        }
                        
                        // Gọi phương thức gốc
                        this.onCharacteristicRead(gatt, characteristic, status);
                    };
                    console.log("[+] Đã hook BluetoothGattCallback.onCharacteristicRead()");
                }
            } catch (e) {
                console.log("[-] Không thể hook BluetoothGatt: " + e.message);
            }
        }
        
        // HOOK YCBTClient - Thu thập dữ liệu từ thiết bị BLE
        function hookYCBTClient() {
            try {
                var YCBTClient = Java.use("com.yucheng.ycbtsdk.YCBTClient");
                
                // Hook tất cả các phương thức trong YCBTClient liên quan đến giấc ngủ
                var methods = YCBTClient.class.getDeclaredMethods();
                for (var i = 0; i < methods.length; i++) {
                    var method = methods[i];
                    var methodName = method.getName();
                    
                    // Ưu tiên các phương thức liên quan đến Sleep, Health
                    if (methodName.toLowerCase().includes("sleep") || 
                        methodName.toLowerCase().includes("health") ||
                        methodName.toLowerCase().includes("history")) {
                        try {
                            (function(mName) {
                                // Lấy tất cả các overload của phương thức
                                var overloads = YCBTClient[mName].overloads;
                                for (var j = 0; j < overloads.length; j++) {
                                    var overload = overloads[j];
                                    overload.implementation = function() {
                                        console.log("\n[+] YCBTClient." + mName + "() được gọi");
                                        console.log("    └── Tham số đầu vào:");
                                        
                                        // In tất cả tham số
                                        for (var k = 0; k < arguments.length; k++) {
                                            console.log("        └── Tham số " + k + ": " + arguments[k]);
                                        }
                                        
                                        // Gọi phương thức gốc
                                        var result = this[mName].apply(this, arguments);
                                        console.log("    └── Kết quả trả về: " + result);
                                        return result;
                                    };
                                }
                                console.log("[+] Đã hook YCBTClient." + mName + "()");
                            })(methodName);
                        } catch (e) {
                            console.log("[-] Không thể hook YCBTClient." + methodName + "(): " + e.message);
                        }
                    }
                }
                
                // Hook phương thức yêu cầu dữ liệu giấc ngủ
                if (YCBTClient.healthHistorySync) {
                    YCBTClient.healthHistorySync.overload('int', 'com.yucheng.ycbtsdk.response.BleDataResponse').implementation = function(type, response) {
                        console.log("\n[+] YCBTClient.healthHistorySync() được gọi");
                        console.log("    └── Tham số đầu vào: type = " + type);
                        
                        var result = this.healthHistorySync(type, response);
                        console.log("    └── Kết quả trả về: " + result);
                        return result;
                    };
                    console.log("[+] Đã hook YCBTClient.healthHistorySync()");
                }
                
                // Hook phương thức xóa dữ liệu sau khi đã đồng bộ
                if (YCBTClient.deleteHealthHistoryData) {
                    YCBTClient.deleteHealthHistoryData.overload('int', 'com.yucheng.ycbtsdk.response.BleDataResponse').implementation = function(type, response) {
                        console.log("\n[+] YCBTClient.deleteHealthHistoryData() được gọi");
                        console.log("    └── Tham số đầu vào: type = " + type);
                        
                        var result = this.deleteHealthHistoryData(type, response);
                        console.log("    └── Kết quả trả về: " + result);
                        return result;
                    };
                    console.log("[+] Đã hook YCBTClient.deleteHealthHistoryData()");
                }
            } catch (e) {
                console.log("[-] Không thể hook YCBTClient: " + e.message);
            }
        }
        
        // HOOK DataUnpack - Giải mã dữ liệu từ thiết bị
        function hookDataUnpack() {
            try {
                var DataUnpack = Java.use("com.yucheng.ycbtsdk.core.DataUnpack");
                
                // Hook phương thức unpackHealthData để giải mã dữ liệu
                if (DataUnpack.unpackHealthData) {
                    DataUnpack.unpackHealthData.overload('[B', 'int').implementation = function(bArr, i2) {
                        console.log("\n[+] DataUnpack.unpackHealthData() được gọi");
                        console.log("    └── Tham số đầu vào:");
                        console.log("        └── i2 (loại dữ liệu) = " + i2);
                        
                        if (bArr != null) {
                            console.log("        └── bArr.length = " + bArr.length);
                            
                            // In toàn bộ dữ liệu hex, không giới hạn
                            if (bArr.length > 0) {
                                var hexString = "";
                                for (var i = 0; i < bArr.length; i++) {
                                    hexString += (bArr[i] & 0xFF).toString(16).padStart(2, '0') + " ";
                                    
                                    // Ngắt dòng sau mỗi 32 byte để dễ đọc
                                    if ((i + 1) % 32 === 0) {
                                        hexString += "\n        ";
                                    }
                                }
                                console.log("        └── Dữ liệu đầy đủ (hex): \n        " + hexString);
                            }
                        } else {
                            console.log("        └── bArr = null");
                        }
                        
                        // Gọi phương thức gốc
                        var result = this.unpackHealthData(bArr, i2);
                        
                        if (result != null) {
                            // In kết quả dưới dạng JSON đầy đủ
                            var gson = Java.use('com.google.gson.Gson').$new();
                            var gsonBuilder = Java.use('com.google.gson.GsonBuilder').$new();
                            var prettyGson = gsonBuilder.setPrettyPrinting().create();
                            
                            try {
                                var jsonString = prettyGson.toJson(result);
                                console.log("    └── Kết quả trả về (JSON đầy đủ): \n" + jsonString);
                            } catch (e) {
                                console.log("    └── Không thể chuyển đổi kết quả sang JSON: " + e.message);
                                
                                // In thông tin cơ bản nếu không thể chuyển JSON
                                console.log("    └── Kết quả trả về (cấu trúc cơ bản): ");
                                console.log("        └── code: " + result.get("code"));
                                console.log("        └── dataType: " + result.get("dataType"));
                                
                                var data = result.get("data");
                                if (data != null) {
                                    console.log("        └── data.size(): " + data.size());
                                    
                                    // In tất cả các bản ghi
                                    for (var i = 0; i < data.size(); i++) {
                                        var record = data.get(i);
                                        console.log("        └── Bản ghi " + i + ": ");
                                        
                                        // In tất cả các key trong record
                                        var keySet = record.keySet().toArray();
                                        for (var j = 0; j < keySet.length; j++) {
                                            var key = keySet[j];
                                            var value = record.get(key);
                                            console.log("            └── " + key + ": " + value);
                                        }
                                    }
                                }
                            }
                        } else {
                            console.log("    └── Kết quả trả về: null");
                        }
                        
                        return result;
                    };
                    console.log("[+] Đã hook DataUnpack.unpackHealthData()");
                }
            } catch (e) {
                console.log("[-] Không thể hook DataUnpack: " + e.message);
            }
        }
        
        // HOOK SleepDbUtils - Lưu dữ liệu vào database
        function hookSleepDbUtils() {
            try {
                var SleepDbUtils = Java.use("com.yucheng.smarthealthpro.greendao.utils.SleepDbUtils");
                
                // Tìm tất cả các phương thức của SleepDbUtils
                var methods = SleepDbUtils.class.getDeclaredMethods();
                for (var i = 0; i < methods.length; i++) {
                    var method = methods[i];
                    var methodName = method.getName();
                    
                    // Hook tất cả các phương thức insert, query, filter
                    if (methodName.startsWith('insert') || methodName.startsWith('query') || methodName.startsWith('filter')) {
                        try {
                            (function(mName) {
                                SleepDbUtils[mName].implementation = function() {
                                    console.log("\n[+] SleepDbUtils." + mName + "() được gọi");
                                    console.log("    └── Tham số đầu vào:");
                                    
                                    // In tất cả tham số
                                    for (var j = 0; j < arguments.length; j++) {
                                        var arg = arguments[j];
                                        console.log("        └── Tham số " + j + ": " + arg);
                                        
                                        // Xử lý các trường hợp đặc biệt
                                        if (arg != null) {
                                            // Trường hợp sleepDb
                                            if (arg.getClass && arg.getClass().getName().includes("SleepDb")) {
                                                console.log("            └── getStartTime(): " + arg.getStartTime());
                                                console.log("            └── getEndTime(): " + arg.getEndTime());
                                                console.log("            └── getDeepSleepTotal(): " + arg.getDeepSleepTotal());
                                                console.log("            └── getLightSleepTotal(): " + arg.getLightSleepTotal());
                                                console.log("            └── getRapidEyeMovementTotal(): " + arg.getRapidEyeMovementTotal());
                                                console.log("            └── getWakeCount(): " + arg.getWakeCount());
                                                console.log("            └── getTimeYearToDate(): " + arg.getTimeYearToDate());
                                            }
                                            
                                            // Trường hợp danh sách
                                            if (arg.getClass && arg.getClass().getName().includes("List")) {
                                                console.log("            └── size(): " + arg.size());
                                                
                                                // In chi tiết tất cả phần tử trong danh sách
                                                if (arg.size() > 0) {
                                                    var gson = Java.use('com.google.gson.Gson').$new();
                                                    var gsonBuilder = Java.use('com.google.gson.GsonBuilder').$new();
                                                    var prettyGson = gsonBuilder.setPrettyPrinting().create();
                                                    
                                                    try {
                                                        for (var k = 0; k < arg.size(); k++) {
                                                            var item = arg.get(k);
                                                            if (item.getClass && item.getClass().getName().includes("SleepDb")) {
                                                                console.log("            └── Phần tử " + k + ":");
                                                                console.log("                └── getStartTime(): " + item.getStartTime());
                                                                console.log("                └── getEndTime(): " + item.getEndTime());
                                                                console.log("                └── getDeepSleepTotal(): " + item.getDeepSleepTotal());
                                                                console.log("                └── getLightSleepTotal(): " + item.getLightSleepTotal());
                                                                console.log("                └── getRapidEyeMovementTotal(): " + item.getRapidEyeMovementTotal());
                                                            } else {
                                                                var itemJson = prettyGson.toJson(item);
                                                                console.log("            └── Phần tử " + k + ": " + itemJson);
                                                            }
                                                        }
                                                    } catch (e) {
                                                        console.log("            └── Không thể chuyển đổi danh sách sang JSON: " + e.message);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    
                                    // Gọi phương thức gốc
                                    var result = this[mName].apply(this, arguments);
                                    console.log("    └── Kết quả trả về: " + result);
                                    
                                    // In chi tiết kết quả nếu là danh sách
                                    if (result != null && result.getClass && result.getClass().getName().includes("List")) {
                                        console.log("        └── Kết quả size(): " + result.size());
                                        
                                        // In chi tiết nếu có phần tử
                                        if (result.size() > 0) {
                                            for (var k = 0; k < result.size(); k++) {
                                                var item = result.get(k);
                                                if (item.getClass && item.getClass().getName().includes("SleepDb")) {
                                                    console.log("        └── Kết quả phần tử " + k + ":");
                                                    console.log("            └── getStartTime(): " + item.getStartTime());
                                                    console.log("            └── getEndTime(): " + item.getEndTime());
                                                    console.log("            └── getDeepSleepTotal(): " + item.getDeepSleepTotal());
                                                    console.log("            └── getLightSleepTotal(): " + item.getLightSleepTotal());
                                                }
                                            }
                                        }
                                    }
                                    
                                    return result;
                                };
                                console.log("[+] Đã hook SleepDbUtils." + mName);
                            })(methodName);
                        } catch (e) {
                            console.log("[-] Không thể hook SleepDbUtils." + methodName + ": " + e.message);
                        }
                    }
                }
            } catch (e) {
                console.log("[-] Không thể hook SleepDbUtils: " + e.message);
            }
        }
        
        // HOOK SleepActivity - Hiển thị dữ liệu
        function hookSleepActivity() {
            try {
                var SleepActivity = Java.use("com.yucheng.smarthealthpro.home.activity.sleep.activity.SleepActivity");
                
                // Hook tất cả các phương thức quan trọng
                var methods = SleepActivity.class.getDeclaredMethods();
                
                for (var i = 0; i < methods.length; i++) {
                    var method = methods[i];
                    var methodName = method.getName();
                    
                    // Chỉ hook các phương thức quan trọng liên quan đến dữ liệu giấc ngủ
                    if (methodName.includes("Sleep") || 
                        methodName.includes("Data") || 
                        methodName.includes("parse") ||
                        methodName.includes("get") && methodName.length > 3) {
                        
                        try {
                            (function(mName) {
                                SleepActivity[mName].implementation = function() {
                                    console.log("\n[+] SleepActivity." + mName + "() được gọi");
                                    console.log("    └── Tham số đầu vào:");
                                    
                                    // In tất cả tham số
                                    for (var j = 0; j < arguments.length; j++) {
                                        var arg = arguments[j];
                                        console.log("        └── Tham số " + j + ": " + arg);
                                        
                                        // In chi tiết nếu là JSON
                                        if (arg != null && typeof arg === 'string' && arg.startsWith("{") && arg.endsWith("}")) {
                                            try {
                                                var gson = Java.use('com.google.gson.Gson').$new();
                                                var gsonBuilder = Java.use('com.google.gson.GsonBuilder').$new();
                                                var prettyGson = gsonBuilder.setPrettyPrinting().create();
                                                
                                                // Parse và in ra định dạng đẹp hơn
                                                var jsonObj = gson.fromJson(arg, Java.use('com.google.gson.JsonObject').class);
                                                var prettyJson = prettyGson.toJson(jsonObj);
                                                console.log("        └── JSON chi tiết: \n" + prettyJson);
                                            } catch (e) {
                                                // Không phải JSON hợp lệ, bỏ qua
                                            }
                                        }
                                    }
                                    
                                    // Gọi phương thức gốc
                                    var result = this[mName].apply(this, arguments);
                                    
                                    // In kết quả nếu có
                                    if (result !== undefined) {
                                        console.log("    └── Kết quả trả về: " + result);
                                        
                                        // In chi tiết kết quả nếu là danh sách
                                        if (result != null && result.getClass && result.getClass().getName().includes("List")) {
                                            console.log("        └── Kết quả size(): " + result.size());
                                        }
                                    }
                                    
                                    // In trạng thái của các biến quan trọng sau khi gọi phương thức
                                    if (mName.includes("parse") || mName.includes("set") || mName.includes("get")) {
                                        console.log("    └── Trạng thái sau khi gọi:");
                                        
                                        if (this.mDaySleepDeepSleepTotal !== undefined) {
                                            console.log("        └── mDaySleepDeepSleepTotal = " + this.mDaySleepDeepSleepTotal);
                                        }
                                        
                                        if (this.mDaySleepLightSleepTotal !== undefined) {
                                            console.log("        └── mDaySleepLightSleepTotal = " + this.mDaySleepLightSleepTotal);
                                        }
                                        
                                        if (this.mDaySleepRemTotal !== undefined) {
                                            console.log("        └── mDaySleepRemTotal = " + this.mDaySleepRemTotal);
                                        }
                                        
                                        if (this.mDaySleepWakeCount !== undefined) {
                                            console.log("        └── mDaySleepWakeCount = " + this.mDaySleepWakeCount);
                                        }
                                        
                                        // In kích thước của danh sách nếu có
                                        if (this.mDaySleepAdapterHisListBean !== undefined && this.mDaySleepAdapterHisListBean !== null) {
                                            console.log("        └── mDaySleepAdapterHisListBean.size = " + this.mDaySleepAdapterHisListBean.size());
                                        }
                                    }
                                    
                                    return result;
                                };
                                console.log("[+] Đã hook SleepActivity." + mName + "()");
                            })(methodName);
                        } catch (e) {
                            console.log("[-] Không thể hook SleepActivity." + methodName + ": " + e.message);
                        }
                    }
                }
            } catch (e) {
                console.log("[-] Không thể hook SleepActivity: " + e.message);
            }
        }
        
        // HOOK Sleep2Activity - Hiển thị dữ liệu
        function hookSleep2Activity() {
            try {
                var Sleep2Activity = Java.use("com.yucheng.smarthealthpro.home.activity.sleep.activity.Sleep2Activity");
                
                // Hook tất cả các phương thức quan trọng
                var methods = Sleep2Activity.class.getDeclaredMethods();
                
                for (var i = 0; i < methods.length; i++) {
                    var method = methods[i];
                    var methodName = method.getName();
                    
                    // Chỉ hook các phương thức quan trọng liên quan đến dữ liệu giấc ngủ
                    if (methodName.includes("Sleep") || 
                        methodName.includes("Data") || 
                        methodName.includes("parse") ||
                        methodName.includes("get") && methodName.length > 3) {
                        
                        try {
                            (function(mName) {
                                Sleep2Activity[mName].implementation = function() {
                                    console.log("\n[+] Sleep2Activity." + mName + "() được gọi");
                                    console.log("    └── Tham số đầu vào:");
                                    
                                    // In tất cả tham số
                                    for (var j = 0; j < arguments.length; j++) {
                                        var arg = arguments[j];
                                        console.log("        └── Tham số " + j + ": " + arg);
                                        
                                        // In chi tiết nếu là JSON
                                        if (arg != null && typeof arg === 'string' && arg.startsWith("{") && arg.endsWith("}")) {
                                            try {
                                                var gson = Java.use('com.google.gson.Gson').$new();
                                                var gsonBuilder = Java.use('com.google.gson.GsonBuilder').$new();
                                                var prettyGson = gsonBuilder.setPrettyPrinting().create();
                                                
                                                // Parse và in ra định dạng đẹp hơn
                                                var jsonObj = gson.fromJson(arg, Java.use('com.google.gson.JsonObject').class);
                                                var prettyJson = prettyGson.toJson(jsonObj);
                                                console.log("        └── JSON chi tiết: \n" + prettyJson);
                                            } catch (e) {
                                                // Không phải JSON hợp lệ, bỏ qua
                                            }
                                        }
                                    }
                                    
                                    // Gọi phương thức gốc
                                    var result = this[mName].apply(this, arguments);
                                    
                                    // In kết quả nếu có
                                    if (result !== undefined) {
                                        console.log("    └── Kết quả trả về: " + result);
                                        
                                        // In chi tiết kết quả nếu là danh sách
                                        if (result != null && result.getClass && result.getClass().getName().includes("List")) {
                                            console.log("        └── Kết quả size(): " + result.size());
                                        }
                                    }
                                    
                                    // In trạng thái của các biến quan trọng sau khi gọi phương thức
                                    if (mName.includes("parse") || mName.includes("set") || mName.includes("get")) {
                                        console.log("    └── Trạng thái sau khi gọi:");
                                        
                                        if (this.mDaySleepDeepSleepTotal !== undefined) {
                                            console.log("        └── mDaySleepDeepSleepTotal = " + this.mDaySleepDeepSleepTotal);
                                        }
                                        
                                        if (this.mDaySleepLightSleepTotal !== undefined) {
                                            console.log("        └── mDaySleepLightSleepTotal = " + this.mDaySleepLightSleepTotal);
                                        }
                                        
                                        if (this.mDaySleepRemTotal !== undefined) {
                                            console.log("        └── mDaySleepRemTotal = " + this.mDaySleepRemTotal);
                                        }
                                        
                                        if (this.mDaySleepWakeCount !== undefined) {
                                            console.log("        └── mDaySleepWakeCount = " + this.mDaySleepWakeCount);
                                        }
                                        
                                        // In kích thước của danh sách nếu có
                                        if (this.mDaySleepAdapterHisListBean !== undefined && this.mDaySleepAdapterHisListBean !== null) {
                                            console.log("        └── mDaySleepAdapterHisListBean.size = " + this.mDaySleepAdapterHisListBean.size());
                                        }
                                    }
                                    
                                    return result;
                                };
                                console.log("[+] Đã hook Sleep2Activity." + mName + "()");
                            })(methodName);
                        } catch (e) {
                            console.log("[-] Không thể hook Sleep2Activity." + methodName + ": " + e.message);
                        }
                    }
                }
            } catch (e) {
                console.log("[-] Không thể hook Sleep2Activity: " + e.message);
            }
        }
        
        // HOOK SleepResponse - Chuyển đổi dữ liệu
        function hookSleepResponse() {
            try {
                // Hook constructor của SleepDataBean
                var SleepResponseDataBean = Java.use("com.yucheng.smarthealthpro.home.bean.SleepResponse$SleepDataBean");
                
                SleepResponseDataBean.$init.overload('int', 'int', 'long', 'long', 'int', 'int', 'int', 'int', 'int', 'java.util.List', 'boolean').implementation = function(deepSleepCount, lightSleepCount, startTime, endTime, deepSleepTotal, lightSleepTotal, rapidEyeMovementTotal, wakeCount, wakeDuration, sleepData, isUpload) {
                    console.log("\n[+] SleepResponse$SleepDataBean constructor được gọi");
                    console.log("    └── Tham số đầu vào:");
                    console.log("        └── deepSleepCount = " + deepSleepCount);
                    console.log("        └── lightSleepCount = " + lightSleepCount);
                    console.log("        └── startTime = " + startTime);
                    console.log("        └── endTime = " + endTime);
                    console.log("        └── deepSleepTotal = " + deepSleepTotal);
                    console.log("        └── lightSleepTotal = " + lightSleepTotal);
                    console.log("        └── rapidEyeMovementTotal = " + rapidEyeMovementTotal);
                    console.log("        └── wakeCount = " + wakeCount);
                    console.log("        └── wakeDuration = " + wakeDuration);
                    
                    if (sleepData != null) {
                        console.log("        └── sleepData.size() = " + sleepData.size());
                        
                        // In chi tiết về dữ liệu giấc ngủ
                        if (sleepData.size() > 0) {
                            for (var i = 0; i < sleepData.size(); i++) {
                                var item = sleepData.get(i);
                                console.log("            └── SleepData[" + i + "]:");
                                console.log("                └── sleepStartTime = " + item.getSleepStartTime());
                                console.log("                └── sleepLen = " + item.getSleepLen());
                                console.log("                └── sleepType = " + item.getSleepType() + " (" + getSleepTypeString(item.getSleepType()) + ")");
                            }
                        }
                    } else {
                        console.log("        └── sleepData = null");
                    }
                    
                    console.log("        └── isUpload = " + isUpload);
                    
                    return this.$init(deepSleepCount, lightSleepCount, startTime, endTime, deepSleepTotal, lightSleepTotal, rapidEyeMovementTotal, wakeCount, wakeDuration, sleepData, isUpload);
                };
                console.log("[+] Đã hook SleepResponse$SleepDataBean constructor");
                
                // Hook constructor của SleepData
                var SleepData = Java.use("com.yucheng.smarthealthpro.home.bean.SleepResponse$SleepDataBean$SleepData");
                
                SleepData.$init.overload('long', 'int', 'int').implementation = function(sleepStartTime, sleepLen, sleepType) {
                    console.log("\n[+] SleepResponse$SleepDataBean$SleepData constructor được gọi");
                    console.log("    └── Tham số đầu vào:");
                    console.log("        └── sleepStartTime = " + sleepStartTime);
                    console.log("        └── sleepLen = " + sleepLen);
                    console.log("        └── sleepType = " + sleepType + " (" + getSleepTypeString(sleepType) + ")");
                    
                    return this.$init(sleepStartTime, sleepLen, sleepType);
                };
                console.log("[+] Đã hook SleepResponse$SleepDataBean$SleepData constructor");
                
            } catch (e) {
                console.log("[-] Không thể hook SleepResponse: " + e.message);
            }
        }
        
        // Hàm trợ giúp để lấy mô tả loại giấc ngủ dựa trên mã
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
    } catch (error) {
        console.log("[-] Lỗi chính trong script: " + error.message);
    }
});