Java.perform(function() {
    console.log("[+] Script loaded successfully");
    
    try {
        // 0. Hook vào BluetoothGatt để theo dõi quá trình giao tiếp Bluetooth
        try {
            var BluetoothGatt = Java.use('android.bluetooth.BluetoothGatt');
            
            // Hook vào phương thức readCharacteristic
            if (BluetoothGatt.readCharacteristic) {
                BluetoothGatt.readCharacteristic.overload('android.bluetooth.BluetoothGattCharacteristic').implementation = function(characteristic) {
                    console.log("[+] BluetoothGatt.readCharacteristic được gọi");
                    
                    if (characteristic != null) {
                        var uuid = characteristic.getUuid();
                        console.log("[+] Đọc characteristic UUID: " + uuid);
                        
                        // Lấy service của characteristic
                        var service = characteristic.getService();
                        if (service != null) {
                            var serviceUuid = service.getUuid();
                            console.log("[+] Service UUID: " + serviceUuid);
                        }
                    }
                    
                    // Gọi phương thức gốc
                    return this.readCharacteristic(characteristic);
                };
                console.log("[+] Đã hook thành công BluetoothGatt.readCharacteristic");
            }
            
            // Hook vào phương thức writeCharacteristic
            if (BluetoothGatt.writeCharacteristic) {
                BluetoothGatt.writeCharacteristic.overload('android.bluetooth.BluetoothGattCharacteristic').implementation = function(characteristic) {
                    console.log("[+] BluetoothGatt.writeCharacteristic được gọi");
                    
                    if (characteristic != null) {
                        var uuid = characteristic.getUuid();
                        console.log("[+] Ghi characteristic UUID: " + uuid);
                        
                        // Lấy service của characteristic
                        var service = characteristic.getService();
                        if (service != null) {
                            var serviceUuid = service.getUuid();
                            console.log("[+] Service UUID: " + serviceUuid);
                        }
                        
                        // Lấy giá trị đang được ghi
                        var value = characteristic.getValue();
                        if (value != null) {
                            var hexValue = "";
                            for (var i = 0; i < value.length; i++) {
                                hexValue += (value[i] & 0xFF).toString(16).padStart(2, '0') + " ";
                            }
                            console.log("[+] Giá trị ghi (hex): " + hexValue);
                            
                            // Nếu là lệnh liên quan đến giấc ngủ, ghi lại chi tiết
                            try {
                                if (hexValue.includes("04")) { // Mã lệnh liên quan đến giấc ngủ
                                    console.log("[+] Phát hiện lệnh liên quan đến giấc ngủ!");
                                }
                            } catch (e) {
                                console.log("[-] Lỗi khi phân tích giá trị: " + e);
                            }
                        }
                    }
                    
                    // Gọi phương thức gốc
                    return this.writeCharacteristic(characteristic);
                };
                console.log("[+] Đã hook thành công BluetoothGatt.writeCharacteristic");
            }
            
            // Hook vào phương thức onCharacteristicRead để bắt dữ liệu đọc được
            var BluetoothGattCallback = Java.use('android.bluetooth.BluetoothGattCallback');
            
            BluetoothGattCallback.onCharacteristicRead.implementation = function(gatt, characteristic, status) {
                console.log("[+] BluetoothGattCallback.onCharacteristicRead được gọi");
                console.log("[+] Status: " + status);
                
                if (characteristic != null) {
                    var uuid = characteristic.getUuid();
                    console.log("[+] Đọc dữ liệu từ characteristic UUID: " + uuid);
                    
                    // Lấy giá trị đọc được
                    var value = characteristic.getValue();
                    if (value != null) {
                        var hexValue = "";
                        for (var i = 0; i < value.length; i++) {
                            hexValue += (value[i] & 0xFF).toString(16).padStart(2, '0') + " ";
                        }
                        console.log("[+] Giá trị đọc được (hex): " + hexValue);
                        
                        // Nếu là dữ liệu giấc ngủ, ghi lại chi tiết
                        try {
                            if (hexValue.includes("04")) { // Mã dữ liệu liên quan đến giấc ngủ
                                console.log("[+] Phát hiện dữ liệu giấc ngủ!");
                                console.log("[+] Dữ liệu giấc ngủ thô: " + hexValue);
                            }
                        } catch (e) {
                            console.log("[-] Lỗi khi phân tích giá trị: " + e);
                        }
                    }
                }
                
                // Gọi phương thức gốc
                this.onCharacteristicRead(gatt, characteristic, status);
            };
            console.log("[+] Đã hook thành công BluetoothGattCallback.onCharacteristicRead");
            
            // Hook vào phương thức onCharacteristicWrite để xác nhận dữ liệu đã ghi
            BluetoothGattCallback.onCharacteristicWrite.implementation = function(gatt, characteristic, status) {
                console.log("[+] BluetoothGattCallback.onCharacteristicWrite được gọi");
                console.log("[+] Status: " + status);
                
                if (characteristic != null) {
                    var uuid = characteristic.getUuid();
                    console.log("[+] Ghi dữ liệu vào characteristic UUID: " + uuid);
                }
                
                // Gọi phương thức gốc
                this.onCharacteristicWrite(gatt, characteristic, status);
            };
            console.log("[+] Đã hook thành công BluetoothGattCallback.onCharacteristicWrite");
            
            // Hook vào phương thức onCharacteristicChanged để bắt thông báo
            BluetoothGattCallback.onCharacteristicChanged.implementation = function(gatt, characteristic) {
                console.log("[+] BluetoothGattCallback.onCharacteristicChanged được gọi");
                
                if (characteristic != null) {
                    var uuid = characteristic.getUuid();
                    console.log("[+] Nhận thông báo từ characteristic UUID: " + uuid);
                    
                    // Lấy giá trị thông báo
                    var value = characteristic.getValue();
                    if (value != null) {
                        var hexValue = "";
                        for (var i = 0; i < value.length; i++) {
                            hexValue += (value[i] & 0xFF).toString(16).padStart(2, '0') + " ";
                        }
                        console.log("[+] Giá trị thông báo (hex): " + hexValue);
                        
                        // Nếu là dữ liệu giấc ngủ, ghi lại chi tiết
                        try {
                            if (hexValue.includes("04")) { // Mã dữ liệu liên quan đến giấc ngủ
                                console.log("[+] Phát hiện thông báo dữ liệu giấc ngủ!");
                                console.log("[+] Dữ liệu giấc ngủ thô: " + hexValue);
                            }
                        } catch (e) {
                            console.log("[-] Lỗi khi phân tích giá trị: " + e);
                        }
                    }
                }
                
                // Gọi phương thức gốc
                this.onCharacteristicChanged(gatt, characteristic);
            };
            console.log("[+] Đã hook thành công BluetoothGattCallback.onCharacteristicChanged");
            
        } catch (e) {
            console.log("[-] Không thể hook BluetoothGatt: " + e);
        }
        // 1. Hook vào DataUnpack để theo dõi quá trình giải mã dữ liệu giấc ngủ từ nhẫn
        try {
            var DataUnpack = Java.use('com.yucheng.ycbtsdk.core.DataUnpack');
            
            // Tìm tất cả các phương thức của DataUnpack
            var methods = DataUnpack.class.getDeclaredMethods();
            var unpackHealthDataFound = false;
            
            for (var i = 0; i < methods.length; i++) {
                var method = methods[i];
                var methodName = method.getName();
                
                if (methodName === "unpackHealthData") {
                    unpackHealthDataFound = true;
                    console.log("[+] Tìm thấy phương thức unpackHealthData với tham số: " + method.toString());
                }
            }
            
            if (unpackHealthDataFound) {
                try {
                    // Hook vào phương thức unpackHealthData để xem dữ liệu thô từ nhẫn
                    DataUnpack.unpackHealthData.overload('[B', 'int').implementation = function(bArr, i1) {
                        console.log("[+] DataUnpack.unpackHealthData được gọi");
                        console.log("[+] Loại dữ liệu (i1): " + i1);
                        
                        if (bArr != null) {
                            console.log("[+] Dữ liệu thô từ nhẫn (bArr.length): " + bArr.length);
                            
                            // In 100 byte đầu tiên để phân tích
                            if (bArr.length > 0) {
                                var rawDataHex = "";
                                var length = Math.min(bArr.length, 100);
                                for (var i = 0; i < length; i++) {
                                    rawDataHex += (bArr[i] & 0xFF).toString(16).padStart(2, '0') + " ";
                                }
                                console.log("[+] Raw data (hex): " + rawDataHex);
                            }
                        }
                        
                        // Gọi phương thức gốc để lấy kết quả
                        var result = this.unpackHealthData(bArr, i1);
                        
                        // Kiểm tra xem có phải dữ liệu giấc ngủ không (case 4)
                        if (i1 == 4) {
                            console.log("[+] Đây là dữ liệu thống kê giấc ngủ");
                            console.log("[+] Kết quả giải mã dữ liệu giấc ngủ:");
                            
                            // Hiển thị các thông tin quan trọng từ kết quả
                            if (result != null) {
                                try {
                                    var gson = Java.use('com.google.gson.Gson').$new();
                                    console.log("[+] Dữ liệu đã giải mã: " + gson.toJson(result));
                                } catch (e) {
                                    console.log("[-] Không thể chuyển đổi kết quả sang JSON: " + e);
                                    console.log("[+] Kết quả: " + result.toString());
                                }
                            }
                        }
                        
                        return result;
                    };
                    console.log("[+] Đã hook thành công DataUnpack.unpackHealthData");
                } catch (e) {
                    console.log("[-] Không thể hook DataUnpack.unpackHealthData: " + e);
                }
            } else {
                console.log("[-] Không tìm thấy phương thức unpackHealthData");
            }
        } catch (e) {
            console.log("[-] Không thể hook DataUnpack: " + e);
        }
        
        // 2. Hook vào SleepActivity và Sleep2Activity để theo dõi quá trình lấy và phân tích dữ liệu giấc ngủ
        try {
            var SleepActivity = Java.use('com.yucheng.smarthealthpro.home.activity.sleep.activity.SleepActivity');
            
            if (SleepActivity.parseSleepData) {
                // Theo dõi việc phân tích dữ liệu giấc ngủ
                SleepActivity.parseSleepData.implementation = function(str, i2) {
                    console.log("[+] SleepActivity.parseSleepData được gọi");
                    console.log("[+] Dữ liệu JSON đầu vào: " + str);
                    console.log("[+] Tham số i2: " + i2);
                    
                    // Gọi phương thức gốc
                    this.parseSleepData(str, i2);
                };
                console.log("[+] Đã hook thành công SleepActivity.parseSleepData");
            } else {
                console.log("[-] Không tìm thấy phương thức SleepActivity.parseSleepData");
            }
        } catch (e) {
            console.log("[-] Không thể hook SleepActivity: " + e);
        }
        
        try {
            var Sleep2Activity = Java.use('com.yucheng.smarthealthpro.home.activity.sleep.activity.Sleep2Activity');
            
            if (Sleep2Activity.parseSleepData) {
                Sleep2Activity.parseSleepData.implementation = function(str, i2) {
                    console.log("[+] Sleep2Activity.parseSleepData được gọi");
                    console.log("[+] Dữ liệu JSON đầu vào: " + str);
                    console.log("[+] Tham số i2: " + i2);
                    
                    // Gọi phương thức gốc
                    this.parseSleepData(str, i2);
                };
                console.log("[+] Đã hook thành công Sleep2Activity.parseSleepData");
            } else {
                console.log("[-] Không tìm thấy phương thức Sleep2Activity.parseSleepData");
            }
        } catch (e) {
            console.log("[-] Không thể hook Sleep2Activity: " + e);
        }
        
        // 3. Hook vào YCBTClient để theo dõi quá trình lấy dữ liệu từ nhẫn
        try {
            var YCBTClient = Java.use('com.yucheng.ycbtsdk.YCBTClient');
            
            // Tìm tất cả các phương thức của YCBTClient
            var methods = YCBTClient.class.getDeclaredMethods();
            var healthHistorySyncFound = false;
            
            for (var i = 0; i < methods.length; i++) {
                var method = methods[i];
                var methodName = method.getName();
                
                if (methodName === "healthHistorySync") {
                    healthHistorySyncFound = true;
                    console.log("[+] Tìm thấy phương thức healthHistorySync với tham số: " + method.toString());
                    
                    try {
                        // Hook vào phương thức healthHistorySync
                        YCBTClient[methodName].overload('int', 'com.yucheng.ycbtsdk.response.BleDataResponse').implementation = function(i1, response) {
                            console.log("[+] YCBTClient.healthHistorySync được gọi với loại: " + i1);
                            
                            if (i1 == 4) {
                                console.log("[+] Đang yêu cầu lấy dữ liệu giấc ngủ từ nhẫn");
                            }
                            
                            // Gọi phương thức gốc
                            return this[methodName](i1, response);
                        };
                        console.log("[+] Đã hook thành công YCBTClient.healthHistorySync");
                    } catch (e) {
                        console.log("[-] Không thể hook YCBTClient.healthHistorySync: " + e);
                    }
                }
            }
            
            if (!healthHistorySyncFound) {
                console.log("[-] Không tìm thấy phương thức healthHistorySync trong YCBTClient");
            }
        } catch (e) {
            console.log("[-] Không thể hook YCBTClient: " + e);
        }
        
        // 4. Hook vào SleepDbUtils để theo dõi việc lưu dữ liệu vào cơ sở dữ liệu
        try {
            var SleepDbUtils = Java.use('com.yucheng.smarthealthpro.greendao.utils.SleepDbUtils');
            
            // Tìm tất cả các phương thức của SleepDbUtils
            var methods = SleepDbUtils.class.getDeclaredMethods();
            var insertMethodsFound = false;
            
            for (var i = 0; i < methods.length; i++) {
                var method = methods[i];
                var methodName = method.getName();
                
                if (methodName.startsWith('insert')) {
                    insertMethodsFound = true;
                    console.log("[+] Tìm thấy phương thức insert: " + methodName);
                    
                    try {
                        // Tạo một closure để lưu tên phương thức
                        (function(mName) {
                            SleepDbUtils[mName].implementation = function() {
                                console.log("[+] SleepDbUtils." + mName + " được gọi");
                                
                                // In các tham số đầu vào
                                for (var j = 0; j < arguments.length; j++) {
                                    var arg = arguments[j];
                                    if (arg != null) {
                                        console.log("[+] Tham số " + j + ": " + arg);
                                        
                                        // Kiểm tra nếu là danh sách các bản ghi
                                        if (arg.getClass && arg.getClass().getName().includes("List")) {
                                            try {
                                                var gson = Java.use('com.google.gson.Gson').$new();
                                                console.log("[+] Danh sách đối tượng: " + gson.toJson(arg));
                                            } catch (e) {
                                                console.log("[-] Không thể chuyển đổi danh sách sang JSON: " + e);
                                                console.log("[+] Số lượng phần tử: " + arg.size());
                                            }
                                        }
                                    }
                                }
                                
                                // Gọi phương thức gốc
                                var result = this[mName].apply(this, arguments);
                                console.log("[+] Kết quả: " + result);
                                return result;
                            };
                            console.log("[+] Đã hook thành công " + mName);
                        })(methodName);
                    } catch (e) {
                        console.log("[-] Không thể hook " + methodName + ": " + e);
                    }
                }
            }
            
            if (!insertMethodsFound) {
                console.log("[-] Không tìm thấy phương thức insert nào trong SleepDbUtils");
            }
        } catch (e) {
            console.log("[-] Không thể hook SleepDbUtils: " + e);
        }
        
        // 5. Hook vào SleepResponse để theo dõi quá trình tạo đối tượng dữ liệu giấc ngủ
        try {
            var SleepDataBean = Java.use('com.yucheng.smarthealthpro.home.bean.SleepResponse$SleepDataBean');
            
            // Tìm tất cả các constructor của SleepDataBean
            var constructors = SleepDataBean.class.getDeclaredConstructors();
            var constructorFound = false;
            
            for (var i = 0; i < constructors.length; i++) {
                var constructor = constructors[i];
                console.log("[+] Tìm thấy constructor: " + constructor.toString());
                constructorFound = true;
            }
            
            if (!constructorFound) {
                console.log("[-] Không tìm thấy constructor nào trong SleepDataBean");
            }
            
            try {
                // Hook vào constructor
                SleepDataBean.$init.overload('int', 'int', 'long', 'long', 'int', 'int', 'int', 'int', 'int', 'java.util.List', 'boolean').implementation = function(i1, i2, j1, j2, i3, i4, i5, i6, i7, list, z) {
                    console.log("[+] SleepDataBean được khởi tạo với các tham số:");
                    console.log("[+] deepSleepCount: " + i1);
                    console.log("[+] lightSleepCount: " + i2);
                    console.log("[+] startTime: " + j1);
                    console.log("[+] endTime: " + j2);
                    console.log("[+] deepSleepTotal: " + i3);
                    console.log("[+] lightSleepTotal: " + i4);
                    console.log("[+] rapidEyeMovementTotal: " + i5);
                    console.log("[+] wakeCount: " + i6);
                    console.log("[+] wakeDuration: " + i7);
                    
                    if (list != null) {
                        console.log("[+] sleepData.size: " + list.size());
                        
                        // In ra 3 mục đầu tiên trong danh sách dữ liệu giấc ngủ
                        if (list.size() > 0) {
                            try {
                                var gson = Java.use('com.google.gson.Gson').$new();
                                var max = Math.min(list.size(), 3);
                                for (var i = 0; i < max; i++) {
                                    var item = list.get(i);
                                    console.log("[+] SleepData[" + i + "]: " + gson.toJson(item));
                                }
                            } catch (e) {
                                console.log("[-] Không thể chuyển đổi dữ liệu giấc ngủ sang JSON: " + e);
                            }
                        }
                    }
                    
                    // Gọi phương thức gốc
                    return this.$init(i1, i2, j1, j2, i3, i4, i5, i6, i7, list, z);
                };
                console.log("[+] Đã hook thành công constructor của SleepDataBean");
            } catch (e) {
                console.log("[-] Không thể hook constructor của SleepDataBean: " + e);
            }
        } catch (e) {
            console.log("[-] Không thể hook SleepDataBean: " + e);
        }
        
        console.log("[+] Hoàn tất quá trình hook");
    } catch (e) {
        console.log("[-] Lỗi chính: " + e);
    }
});
