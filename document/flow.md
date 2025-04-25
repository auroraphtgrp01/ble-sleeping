# QUY TRÌNH XỬ LÝ DỮ LIỆU GIẤC NGỦ TỪ THIẾT BỊ BLE ĐẾN CƠ SỞ DỮ LIỆU

## 1. THU THẬP DỮ LIỆU TỪ THIẾT BỊ BLE

### 1.1. Khởi tạo kết nối BLE

- **Tệp**: `YCBTClient.java` và `YCBTClientImpl.java`
- **Package**: `com.yucheng.ycbtsdk`
- **Mô tả**: Thiết lập kết nối Bluetooth Low Energy với thiết bị đeo

### 1.2. Yêu cầu dữ liệu giấc ngủ

- **Tệp**: `YCBTClient.java`
- **Package**: `com.yucheng.ycbtsdk`
- **Phương thức**: `healthHistorySync(int type, BleDataResponse response)`
- **Mô tả**: Gửi yêu cầu lấy dữ liệu giấc ngủ với tham số type = 4 (mã cho dữ liệu giấc ngủ)
- **Đoạn mã**:
  ```java
  YCBTClient.healthHistorySync(4, bleDataResponse);
  ```

### 1.3. Nhận dữ liệu thô
- **Tệp**: `BluetoothGattCallback.java` (Android framework)
- **Phương thức**: `onCharacteristicChanged(BluetoothGatt gatt, BluetoothGattCharacteristic characteristic)`
- **Mô tả**: Nhận dữ liệu thô dạng mảng byte từ thiết bị BLE

## 2. GIẢI MÃ DỮ LIỆU

### 2.1. Giải mã dữ liệu thô
- **Tệp**: `DataUnpack.java`
- **Package**: `com.yucheng.ycbtsdk.core`
- **Phương thức**: `unpackHealthData(byte[] bArr, int i2)`
- **Tham số**:
  - `bArr`: Mảng byte chứa dữ liệu thô từ thiết bị BLE
  - `i2`: Loại dữ liệu (= 4 cho dữ liệu giấc ngủ)
- **Mô tả**: Phân tích và giải mã dữ liệu thô thành các trường có ý nghĩa

### 2.2. Kết quả giải mã
- **Định dạng kết quả**: `HashMap` chứa thông tin về giấc ngủ
- **Cấu trúc HashMap**:
  ```java
  {
    "code": 0,
    "dataType": Constants.DATATYPE.Health_HistorySleep,
    "data": [
      {
        "startTime": <timestamp>,
        "endTime": <timestamp>,
        "deepSleepCount": <int>,
        "lightSleepCount": <int>,
        "deepSleepTotal": <int>,
        "lightSleepTotal": <int>,
        "rapidEyeMovementTotal": <int>,
        "sleepData": <ArrayList>, // Chi tiết các giai đoạn giấc ngủ
        "wakeCount": <int>,
        "wakeDuration": <int>
      },
      // Có thể có nhiều bản ghi
    ]
  }
  ```

## 3. CHUYỂN ĐỔI DỮ LIỆU

### 3.1. Chuyển đổi HashMap thành đối tượng Java
- **Tệp**: `SleepResponse.java`
- **Package**: `com.yucheng.smarthealthpro.home.bean`
- **Mô tả**: Sử dụng thư viện Gson để chuyển đổi dữ liệu từ HashMap thành đối tượng SleepResponse

### 3.2. Cấu trúc đối tượng SleepResponse
- **Tệp**: `SleepResponse.java`
- **Package**: `com.yucheng.smarthealthpro.home.bean`
- **Các trường**:
  - `code`: Mã trạng thái
  - `dataType`: Loại dữ liệu (DATATYPE.Health_HistorySleep)
  - `data`: Danh sách các đối tượng SleepDataBean

### 3.3. Cấu trúc đối tượng SleepDataBean
- **Tệp**: `SleepResponse.java` (lớp inner)
- **Package**: `com.yucheng.smarthealthpro.home.bean`
- **Các trường**:
  - `deepSleepCount`: Số lần ngủ sâu
  - `lightSleepCount`: Số lần ngủ nhẹ
  - `startTime`: Thời gian bắt đầu (timestamp)
  - `endTime`: Thời gian kết thúc (timestamp)
  - `deepSleepTotal`: Tổng thời gian ngủ sâu (giây)
  - `lightSleepTotal`: Tổng thời gian ngủ nhẹ (giây)
  - `rapidEyeMovementTotal`: Tổng thời gian REM (giây)
  - `wakeCount`: Số lần thức giấc
  - `wakeDuration`: Thời gian thức giấc (giây)
  - `sleepData`: Danh sách các đối tượng SleepData (chi tiết từng giai đoạn)
  - `isUpload`: Cờ đánh dấu đã tải lên server hay chưa

### 3.4. Cấu trúc đối tượng SleepData
- **Tệp**: `SleepResponse.java` (lớp inner trong SleepDataBean)
- **Package**: `com.yucheng.smarthealthpro.home.bean`
- **Các trường**:
  - `sleepStartTime`: Thời điểm bắt đầu giai đoạn (timestamp)
  - `sleepLen`: Thời gian kéo dài (giây)
  - `sleepType`: Loại giấc ngủ
    - `241`: Ngủ sâu
    - `242`: Ngủ nhẹ
    - `243`: REM
    - `244`: Thức giấc
    - `-1`: Không xác định

### 3.5. Tạo đối tượng SleepDb để lưu vào cơ sở dữ liệu
- **Tệp**: `SleepActivity.java` hoặc `Sleep2Activity.java`
- **Package**: `com.yucheng.smarthealthpro.home.activity.sleep.activity`
- **Phương thức**: `setDayData()` và `getDaySleepData()`
- **Mô tả**: Xử lý dữ liệu từ SleepResponse và tạo các đối tượng SleepDb để chuẩn bị lưu vào cơ sở dữ liệu

## 4. LƯU TRỮ DỮ LIỆU VÀO CƠ SỞ DỮ LIỆU

### 4.1. Khởi tạo SleepDbUtils
- **Tệp**: `SleepDbUtils.java`
- **Package**: `com.yucheng.smarthealthpro.greendao.utils`
- **Phương thức khởi tạo**:
  ```java
  SleepDbUtils sleepDbUtils = new SleepDbUtils(context);
  ```

### 4.2. Phương thức lưu một bản ghi đơn lẻ
- **Tệp**: `SleepDbUtils.java`
- **Package**: `com.yucheng.smarthealthpro.greendao.utils`
- **Phương thức**: `insertMsgModel(SleepDb sleepDb)`
- **Mô tả**: Lưu một bản ghi SleepDb đơn lẻ vào cơ sở dữ liệu
- **Đoạn mã**:
  ```java
  public boolean insertMsgModel(SleepDb sleepDb) {
      return daoManager.getDaoSession().getSleepDbDao().insert(sleepDb) > 0;
  }
  ```

### 4.3. Phương thức lưu nhiều bản ghi cùng lúc
- **Tệp**: `SleepDbUtils.java`
- **Package**: `com.yucheng.smarthealthpro.greendao.utils`
- **Phương thức**: `insertMultMsgModel(final List<SleepDb> list)`
- **Mô tả**: Lưu nhiều bản ghi SleepDb cùng một lúc trong một giao dịch
- **Đoạn mã**:
  ```java
  public boolean insertMultMsgModel(final List<SleepDb> list) {
      try {
          daoManager.getDaoSession().runInTx(new Runnable() {
              @Override
              public void run() {
                  Iterator it2 = list.iterator();
                  while (it2.hasNext()) {
                      SleepDbUtils.daoManager.getDaoSession().insertOrReplace((SleepDb) it2.next());
                  }
              }
          });
          return true;
      } catch (Exception e2) {
          e2.printStackTrace();
          return false;
      }
  }
  ```

### 4.4. Xóa dữ liệu đã đồng bộ trên thiết bị
- **Tệp**: `YCBTClient.java`
- **Package**: `com.yucheng.ycbtsdk`
- **Phương thức**: `deleteHealthHistoryData(int type, BleDataResponse response)`
- **Mô tả**: Sau khi lưu thành công, xóa dữ liệu đã đồng bộ trên thiết bị
- **Đoạn mã**:
  ```java
  YCBTClient.deleteHealthHistoryData(Constants.DATATYPE.Health_DeleteSleep, bleDataResponse);
  ```

## 5. TRUY VẤN VÀ HIỂN THỊ DỮ LIỆU

### 5.1. Truy vấn dữ liệu giấc ngủ từ cơ sở dữ liệu
- **Tệp**: `SleepDbUtils.java`
- **Package**: `com.yucheng.smarthealthpro.greendao.utils`
- **Phương thức**:
  - `queryIdYearToDay(String date)`: Truy vấn dữ liệu giấc ngủ theo ngày
  - `queryEqTimeYearToDay(String date)`: Truy vấn dữ liệu giấc ngủ chính xác theo ngày
  - `queryGroupId(long timestamp)`: Truy vấn dữ liệu giấc ngủ theo nhóm thời gian
  - `queryByNotUpload()`: Truy vấn dữ liệu chưa được tải lên server

### 5.2. Lọc dữ liệu trước khi hiển thị
- **Tệp**: `SleepDbUtils.java`
- **Package**: `com.yucheng.smarthealthpro.greendao.utils`
- **Phương thức**: `filter(List<SleepDb> list)`
- **Mô tả**: Lọc bỏ các bản ghi không hợp lệ (vượt quá 16 giờ - 57600 giây)
- **Đoạn mã**:
  ```java
  public List<SleepDb> filter(List<SleepDb> list) {
      int i2 = 0;
      while (i2 < list.size()) {
          SleepDb sleepDb = list.get(i2);
          if (sleepDb.getDeepSleepTotal() + sleepDb.getLightSleepTotal() + sleepDb.rapidEyeMovementTotal > 57600) {
              list.remove(i2);
              i2--;
          }
          i2++;
      }
      return list;
  }
  ```

### 5.3. Hiển thị dữ liệu trên giao diện
- **Tệp**: `SleepActivity.java` hoặc `Sleep2Activity.java`
- **Package**: `com.yucheng.smarthealthpro.home.activity.sleep.activity`
- **Phương thức**:
  - `freshDayData()`: Hiển thị dữ liệu theo ngày
  - `freshWeekData()`: Hiển thị dữ liệu theo tuần
  - `freshMonthData()`: Hiển thị dữ liệu theo tháng

## 6. QUY TRÌNH HOÀN CHỈNH

1. **Thu thập dữ liệu**: Gọi `YCBTClient.healthHistorySync(4, bleDataResponse)` để lấy dữ liệu giấc ngủ từ thiết bị BLE
2. **Giải mã dữ liệu**: Dữ liệu thô được truyền vào `DataUnpack.unpackHealthData(bArr, 4)` để giải mã
3. **Chuyển đổi dữ liệu**: Kết quả giải mã được chuyển đổi thành đối tượng `SleepResponse` và `SleepDataBean`
4. **Xử lý dữ liệu**: Dữ liệu được xử lý trong các phương thức `setDayData()` hoặc `getDaySleepData()`
5. **Lưu vào cơ sở dữ liệu**: Gọi `SleepDbUtils.insertMultMsgModel(listSleepDb)` để lưu dữ liệu vào cơ sở dữ liệu
6. **Xóa dữ liệu trên thiết bị**: Gọi `YCBTClient.deleteHealthHistoryData(Constants.DATATYPE.Health_DeleteSleep, bleDataResponse)` 
7. **Truy vấn và hiển thị**: Sử dụng `SleepDbUtils` để truy vấn dữ liệu và hiển thị trên giao diện

## 7. NHỮNG LƯU Ý QUAN TRỌNG

1. **Giới hạn thời gian giấc ngủ**: Dữ liệu giấc ngủ có giới hạn tối đa 16 giờ (57600 giây)
2. **Xử lý trùng lặp**: Dữ liệu được kiểm tra và loại bỏ trùng lặp trước khi lưu hoặc hiển thị
3. **Lọc dữ liệu**: Phương thức `filter()` được sử dụng để đảm bảo chỉ lưu và hiển thị dữ liệu hợp lệ
4. **Giao dịch DB**: Việc lưu nhiều bản ghi được thực hiện trong một giao dịch để đảm bảo tính nhất quán của dữ liệu