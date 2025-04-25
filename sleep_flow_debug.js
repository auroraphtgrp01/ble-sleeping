Java.perform(function () {
    // Hàm hỗ trợ ghi log ra file
    function writeToLogFile(message) {
        try {
            // Đường dẫn đến file log
            var logFilePath = "/storage/emulated/0/Podcasts/sleep_debug_log.txt";

            // Lấy thời gian hiện tại để thêm timestamp vào log
            var currentDate = new Date();
            var timestamp = currentDate.toLocaleString();

            // Tạo nội dung log với timestamp
            var logContent = "[" + timestamp + "] " + message + "\n";

            // Kiểm tra quyền đọc/ghi bộ nhớ ngoài
            var Environment = Java.use("android.os.Environment");
            var File = Java.use("java.io.File");
            var FileOutputStream = Java.use("java.io.FileOutputStream");
            var OutputStreamWriter = Java.use("java.io.OutputStreamWriter");
            var BufferedWriter = Java.use("java.io.BufferedWriter");

            // Kiểm tra trạng thái bộ nhớ ngoài
            if (Environment.getExternalStorageState().equals(Environment.MEDIA_MOUNTED)) {
                // Tạo thư mục nếu chưa tồn tại
                var logDir = new File("/storage/emulated/0/Podcasts");
                if (!logDir.exists()) {
                    logDir.mkdirs();
                }

                // Tạo file log nếu chưa tồn tại
                var logFile = new File(logFilePath);

                // Mở file để ghi (append mode)
                var fos = new FileOutputStream(logFile, true);
                var osw = new OutputStreamWriter(fos);
                var bw = new BufferedWriter(osw);

                // Ghi nội dung log
                bw.write(logContent);

                // Đóng file
                bw.close();
                osw.close();
                fos.close();

                // Ghi thành công
                return true;
            } else {
                console.log("[-] Không thể ghi log: Bộ nhớ ngoài không khả dụng");
                return false;
            }
        } catch (e) {
            console.log("[-] Lỗi khi ghi log: " + e.message);
            return false;
        }
    }

    var originalConsoleLog = console.log;

    // Ghi đè hàm console.log để tự động ghi ra file
    console.log = function (message) {
        // Gọi hàm console.log gốc
        originalConsoleLog(message);

        // Ghi ra file
        writeToLogFile(message);
    };

    console.log("[+] Script debug luồng dữ liệu giấc ngủ đã được tải");
    console.log("[+] Đã thiết lập ghi log ra file: /storage/emulated/0/Podcasts/sleep_debug_log.txt");

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

        console.log("[+] Đã hook thành công các phương thức liên quan đến luồng dữ liệu giấc ngủ");
    } catch (e) {
        console.log("[-] Lỗi: " + e.message);
    }

    // HOOK YCBTClient - Thu thập dữ liệu từ thiết bị BLE
    function hookYCBTClient() {
        try {
            var YCBTClient = Java.use("com.yucheng.ycbtsdk.YCBTClient");

            // Hook phương thức yêu cầu dữ liệu giấc ngủ
            if (YCBTClient.healthHistorySync) {
                YCBTClient.healthHistorySync.overload('int', 'com.yucheng.ycbtsdk.response.BleDataResponse').implementation = function (type, response) {
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
                YCBTClient.deleteHealthHistoryData.overload('int', 'com.yucheng.ycbtsdk.response.BleDataResponse').implementation = function (type, response) {
                    console.log("\n[+] YCBTClient.deleteHealthHistoryData() được gọi");
                    console.log("    └── Tham số đầu vào: type = " + type);

                    // Kiểm tra nếu là yêu cầu xóa dữ liệu giấc ngủ (type = 4)
                    if (type === 4) {
                        console.log("    └── ĐÃ CHẶN XÓA DỮ LIỆU GIẤC NGỦ!");
                        return true;
                    }

                    var result = this.deleteHealthHistoryData(type, response);
                    console.log("    └── Kết quả trả về: " + result);
                    return result;
                };
                console.log("[+] Đã hook YCBTClient.deleteHealthHistoryData() với chức năng chặn xóa dữ liệu giấc ngủ");
            }
        } catch (e) {
            console.log("[-] Không thể hook YCBTClient: " + e.message);
        }
    }

    // HOOK DataUnpack - Giải mã dữ liệu từ thiết bị
    function hookDataUnpack() {
        try {
            var DataUnpack = Java.use("com.yucheng.ycbtsdk.core.DataUnpack");

            if (DataUnpack.unpackHealthData) {
                DataUnpack.unpackHealthData.overload('[B', 'int').implementation = function (bArr, i2) {
                    console.log("\n[+] DataUnpack.unpackHealthData() được gọi");
                    console.log("    └── Tham số đầu vào:");
                    console.log("        └── i2 (loại dữ liệu) = " + i2);
                    if (bArr != null) {
                        console.log("        └── bArr.length = " + bArr.length);

                        // In đầy đủ dữ liệu byte nhận được
                        if (bArr.length > 0) {
                            var hexString = "";
                            for (var i = 0; i < bArr.length; i++) {
                                hexString += (bArr[i] & 0xFF).toString(16).padStart(2, '0') + " ";
                                if ((i + 1) % 20 === 0 && i < bArr.length - 1) {
                                    hexString += "\n                        ";
                                }
                            }
                            console.log("        └── Dữ liệu đầy đủ: ");
                            console.log("            " + hexString);
                        }
                    } else {
                        console.log("        └── bArr = null");
                    }

                    var result = this.unpackHealthData(bArr, i2);

                    if (result != null) {
                        var gson = Java.use('com.google.gson.Gson').$new();
                        try {
                            var jsonString = gson.toJson(result);
                            console.log("RAW: jsonString", jsonString)
                            console.log("    └── Kết quả trả về (cấu trúc): ");
                            console.log("        └── code: " + result.get("code"));
                            console.log("        └── dataType: " + result.get("dataType"));

                            var data = result.get("data");
                            if (data != null) {
                                console.log("        └── data.size(): " + data.size());
                                if (data.size() > 0) {
                                    console.log("        └── Bản ghi đầu tiên: ");
                                    var firstRecord = data.get(0);
                                    console.log("            └── startTime: " + firstRecord.get("startTime"));
                                    console.log("            └── endTime: " + firstRecord.get("endTime"));
                                    console.log("            └── deepSleepTotal: " + firstRecord.get("deepSleepTotal"));
                                    console.log("            └── lightSleepTotal: " + firstRecord.get("lightSleepTotal"));
                                }
                            }
                        } catch (e) {
                            console.log("    └── Không thể chuyển đổi kết quả sang JSON: " + e.message);
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

            // Hook phương thức insertMsgModel (lưu một bản ghi)
            if (SleepDbUtils.insertMsgModel) {
                SleepDbUtils.insertMsgModel.implementation = function (sleepDb) {
                    console.log("\n[+] SleepDbUtils.insertMsgModel() được gọi");
                    console.log("    └── Tham số đầu vào:");

                    if (sleepDb != null) {
                        console.log("        └── sleepDb.getStartTime(): " + sleepDb.getStartTime());
                        console.log("        └── sleepDb.getEndTime(): " + sleepDb.getEndTime());
                        console.log("        └── sleepDb.getDeepSleepTotal(): " + sleepDb.getDeepSleepTotal());
                        console.log("        └── sleepDb.getLightSleepTotal(): " + sleepDb.getLightSleepTotal());
                        console.log("        └── sleepDb.getTimeYearToDate(): " + sleepDb.getTimeYearToDate());
                    } else {
                        console.log("        └── sleepDb = null");
                    }

                    var result = this.insertMsgModel(sleepDb);
                    console.log("    └── Kết quả trả về: " + result);
                    return result;
                };
                console.log("[+] Đã hook SleepDbUtils.insertMsgModel()");
            }

            // Hook phương thức insertMultMsgModel (lưu nhiều bản ghi)
            if (SleepDbUtils.insertMultMsgModel) {
                SleepDbUtils.insertMultMsgModel.implementation = function (list) {
                    console.log("\n[+] SleepDbUtils.insertMultMsgModel() được gọi");
                    console.log("    └── Tham số đầu vào:");

                    if (list != null) {
                        console.log("        └── list.size(): " + list.size());

                        if (list.size() > 0) {
                            // In thông tin của bản ghi đầu tiên
                            var firstItem = list.get(0);
                            console.log("        └── Bản ghi đầu tiên:");
                            console.log("            └── getStartTime(): " + firstItem.getStartTime());
                            console.log("            └── getEndTime(): " + firstItem.getEndTime());
                            console.log("            └── getDeepSleepTotal(): " + firstItem.getDeepSleepTotal());
                            console.log("            └── getLightSleepTotal(): " + firstItem.getLightSleepTotal());
                        }
                    } else {
                        console.log("        └── list = null");
                    }

                    var result = this.insertMultMsgModel(list);
                    console.log("    └── Kết quả trả về: " + result);
                    return result;
                };
                console.log("[+] Đã hook SleepDbUtils.insertMultMsgModel()");
            }

            // Hook phương thức filter 
            if (SleepDbUtils.filter) {
                SleepDbUtils.filter.implementation = function (list) {
                    console.log("\n[+] SleepDbUtils.filter() được gọi");
                    console.log("    └── Tham số đầu vào:");

                    if (list != null) {
                        console.log("        └── list.size() trước khi lọc: " + list.size());
                    } else {
                        console.log("        └── list = null");
                    }

                    var result = this.filter(list);

                    if (result != null) {
                        console.log("    └── Kết quả trả về:");
                        console.log("        └── list.size() sau khi lọc: " + result.size());
                    } else {
                        console.log("    └── Kết quả trả về: null");
                    }

                    return result;
                };
                console.log("[+] Đã hook SleepDbUtils.filter()");
            }

            // Hook phương thức queryIdYearToDay
            if (SleepDbUtils.queryIdYearToDay) {
                SleepDbUtils.queryIdYearToDay.implementation = function (date) {
                    console.log("\n[+] SleepDbUtils.queryIdYearToDay() được gọi");
                    console.log("    └── Tham số đầu vào: date = " + date);

                    var result = this.queryIdYearToDay(date);

                    if (result != null) {
                        console.log("    └── Kết quả trả về: số lượng bản ghi = " + result.size());
                    } else {
                        console.log("    └── Kết quả trả về: null");
                    }

                    return result;
                };
                console.log("[+] Đã hook SleepDbUtils.queryIdYearToDay()");
            }

            // Hook phương thức queryEqTimeYearToDay
            if (SleepDbUtils.queryEqTimeYearToDay) {
                SleepDbUtils.queryEqTimeYearToDay.implementation = function (date) {
                    console.log("\n[+] SleepDbUtils.queryEqTimeYearToDay() được gọi");
                    console.log("    └── Tham số đầu vào: date = " + date);

                    var result = this.queryEqTimeYearToDay(date);

                    if (result != null) {
                        console.log("    └── Kết quả trả về: số lượng bản ghi = " + result.size());
                    } else {
                        console.log("    └── Kết quả trả về: null");
                    }

                    return result;
                };
                console.log("[+] Đã hook SleepDbUtils.queryEqTimeYearToDay()");
            }
        } catch (e) {
            console.log("[-] Không thể hook SleepDbUtils: " + e.message);
        }
    }

    // HOOK SleepActivity - Hiển thị dữ liệu
    function hookSleepActivity() {
        try {
            var SleepActivity = Java.use("com.yucheng.smarthealthpro.home.activity.sleep.activity.SleepActivity");

            // Hook phương thức setDayData
            if (SleepActivity.setDayData) {
                SleepActivity.setDayData.implementation = function () {
                    console.log("\n[+] SleepActivity.setDayData() được gọi");

                    if (this.mLists != null) {
                        console.log("    └── Dữ liệu đầu vào: mLists.size() = " + this.mLists.size());
                    }

                    this.setDayData();

                    console.log("    └── Kết quả sau khi xử lý:");
                    console.log("        └── mDaySleepDeepSleepTotal = " + this.mDaySleepDeepSleepTotal);
                    console.log("        └── mDaySleepLightSleepTotal = " + this.mDaySleepLightSleepTotal);
                    console.log("        └── mDaySleepRemTotal = " + this.mDaySleepRemTotal);
                    console.log("        └── mDaySleepWakeCount = " + this.mDaySleepWakeCount);
                };
                console.log("[+] Đã hook SleepActivity.setDayData()");
            }

            // Hook phương thức getDaySleepData
            if (SleepActivity.getDaySleepData) {
                SleepActivity.getDaySleepData.implementation = function (str, i2) {
                    console.log("\n[+] SleepActivity.getDaySleepData() được gọi");
                    console.log("    └── Tham số đầu vào:");
                    console.log("        └── str (date) = " + str);
                    console.log("        └── i2 = " + i2);

                    this.getDaySleepData(str, i2);

                    console.log("    └── Kết quả sau khi xử lý:");
                    if (this.mSleepDb != null) {
                        console.log("        └── mSleepDb.size() = " + this.mSleepDb.size());
                    }
                    console.log("        └── mDaySleepAdapterHisListBean.size() = " + this.mDaySleepAdapterHisListBean.size());
                };
                console.log("[+] Đã hook SleepActivity.getDaySleepData()");
            }

            // Hook phương thức parseSleepData
            if (SleepActivity.parseSleepData) {
                SleepActivity.parseSleepData.implementation = function (str, i2) {
                    console.log("\n[+] SleepActivity.parseSleepData() được gọi");
                    console.log("    └── Tham số đầu vào:");
                    console.log("        └── i2 = " + i2);

                    this.parseSleepData(str, i2);

                    console.log("    └── Kết quả sau khi xử lý:");
                    if (i2 == 7) {
                        console.log("        └── mWeekSleepAverageDeepSleepTotal = " + this.mWeekSleepAverageDeepSleepTotal);
                        console.log("        └── mWeekSleepAverageLightSleepTotal = " + this.mWeekSleepAverageLightSleepTotal);
                        console.log("        └── mWeekSleepAdapterHisListBean.size() = " + this.mWeekSleepAdapterHisListBean.size());
                    } else if (i2 == 30) {
                        console.log("        └── mMonthSleepAverageDeepSleepTotal = " + this.mMonthSleepAverageDeepSleepTotal);
                        console.log("        └── mMonthSleepAverageLightSleepTotal = " + this.mMonthSleepAverageLightSleepTotal);
                        console.log("        └── mMonthSleepAdapterHisListBean.size() = " + this.mMonthSleepAdapterHisListBean.size());
                    }
                };
                console.log("[+] Đã hook SleepActivity.parseSleepData()");
            }
        } catch (e) {
            console.log("[-] Không thể hook SleepActivity: " + e.message);
        }
    }

    // HOOK Sleep2Activity - Hiển thị dữ liệu
    function hookSleep2Activity() {
        try {
            var Sleep2Activity = Java.use("com.yucheng.smarthealthpro.home.activity.sleep.activity.Sleep2Activity");

            // Hook phương thức setDayData
            if (Sleep2Activity.setDayData) {
                Sleep2Activity.setDayData.implementation = function () {
                    console.log("\n[+] Sleep2Activity.setDayData() được gọi");

                    if (this.mLists != null) {
                        console.log("    └── Dữ liệu đầu vào: mLists.size() = " + this.mLists.size());
                    }

                    this.setDayData();

                    console.log("    └── Kết quả sau khi xử lý:");
                    console.log("        └── mDaySleepDeepSleepTotal = " + this.mDaySleepDeepSleepTotal);
                    console.log("        └── mDaySleepLightSleepTotal = " + this.mDaySleepLightSleepTotal);
                    console.log("        └── mDaySleepRemTotal = " + this.mDaySleepRemTotal);
                    console.log("        └── mDaySleepWakeCount = " + this.mDaySleepWakeCount);
                };
                console.log("[+] Đã hook Sleep2Activity.setDayData()");
            }

            // Hook phương thức getDaySleepData
            if (Sleep2Activity.getDaySleepData) {
                Sleep2Activity.getDaySleepData.implementation = function (str, i2) {
                    console.log("\n[+] Sleep2Activity.getDaySleepData() được gọi");
                    console.log("    └── Tham số đầu vào:");
                    console.log("        └── str (date) = " + str);
                    console.log("        └── i2 = " + i2);

                    this.getDaySleepData(str, i2);

                    console.log("    └── Kết quả sau khi xử lý:");
                    if (this.mSleepDb != null) {
                        console.log("        └── mSleepDb.size() = " + this.mSleepDb.size());
                    }
                    console.log("        └── mDaySleepAdapterHisListBean.size() = " + this.mDaySleepAdapterHisListBean.size());
                };
                console.log("[+] Đã hook Sleep2Activity.getDaySleepData()");
            }

            // Hook phương thức parseSleepData
            if (Sleep2Activity.parseSleepData) {
                Sleep2Activity.parseSleepData.implementation = function (str, i2) {
                    console.log("\n[+] Sleep2Activity.parseSleepData() được gọi");
                    console.log("    └── Tham số đầu vào:");
                    console.log("        └── i2 = " + i2);

                    this.parseSleepData(str, i2);

                    console.log("    └── Kết quả sau khi xử lý:");
                    if (i2 == 7) {
                        console.log("        └── mWeekSleepAverageDeepSleepTotal = " + this.mWeekSleepAverageDeepSleepTotal);
                        console.log("        └── mWeekSleepAverageLightSleepTotal = " + this.mWeekSleepAverageLightSleepTotal);
                        console.log("        └── mWeekSleepAdapterHisListBean.size() = " + this.mWeekSleepAdapterHisListBean.size());
                    } else if (i2 == 30) {
                        console.log("        └── mMonthSleepAverageDeepSleepTotal = " + this.mMonthSleepAverageDeepSleepTotal);
                        console.log("        └── mMonthSleepAverageLightSleepTotal = " + this.mMonthSleepAverageLightSleepTotal);
                        console.log("        └── mMonthSleepAdapterHisListBean.size() = " + this.mMonthSleepAdapterHisListBean.size());
                    }
                };
                console.log("[+] Đã hook Sleep2Activity.parseSleepData()");
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

            SleepResponseDataBean.$init.overload('int', 'int', 'long', 'long', 'int', 'int', 'int', 'int', 'int', 'java.util.List', 'boolean').implementation = function (deepSleepCount, lightSleepCount, startTime, endTime, deepSleepTotal, lightSleepTotal, rapidEyeMovementTotal, wakeCount, wakeDuration, sleepData, isUpload) {
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
                } else {
                    console.log("        └── sleepData = null");
                }

                console.log("        └── isUpload = " + isUpload);

                return this.$init(deepSleepCount, lightSleepCount, startTime, endTime, deepSleepTotal, lightSleepTotal, rapidEyeMovementTotal, wakeCount, wakeDuration, sleepData, isUpload);
            };
            console.log("[+] Đã hook SleepResponse$SleepDataBean constructor");

            // Hook constructor của SleepData
            var SleepData = Java.use("com.yucheng.smarthealthpro.home.bean.SleepResponse$SleepDataBean$SleepData");

            SleepData.$init.overload('long', 'int', 'int').implementation = function (sleepStartTime, sleepLen, sleepType) {
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
});