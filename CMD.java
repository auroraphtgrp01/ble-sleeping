package com.yucheng.ycbtsdk.core;

/* loaded from: classes4.dex */
public class CMD {
    public static final int AppControl = 3;
    public static String BLETAG = "YCBLE";
    public static final int Collect = 7;
    public static final int CollectionTools = 19;
    public static final int Customize = 13;
    public static final String DEFAULT_DFU_SERVICE_UUID = "0000fe59-0000-1000-8000-00805f9b34fb";
    public static final int DevControl = 4;
    public static final int Dial = 9;
    public static final int Factory = 8;
    public static final int Get = 2;
    public static final int Health = 5;
    public static final String JL_UUID_NOTIFICATION = "0000ae02-0000-1000-8000-00805f9b34fb";
    public static final String JL_UUID_SERVICE = "0000ae00-0000-1000-8000-00805f9b34fb";
    public static final String JL_UUID_WRITE = "0000ae01-0000-1000-8000-00805f9b34fb";
    public static final int OtaDevice = 10;
    public static final int OtaUI = 126;
    public static final int Priority_high = 3;
    public static final int Priority_low = 1;
    public static final int Priority_normal = 2;
    public static final int Real = 6;
    public static final int SelfInspection = 12;
    public static final int Setting = 1;
    public static final int TestTool = 14;
    public static final String UART_RX_CHARACTERISTIC = "6E400002-B5A3-F393-E0A9-E50E24DCCA9E";
    public static final String UART_SERVICE_UUID = "6E400001-B5A3-F393-E0A9-E50E24DCCA9E";
    public static final String UART_TX_CHARACTERISTIC = "6E400003-B5A3-F393-E0A9-E50E24DCCA9E";
    public static final String UUID_C_1 = "be940001-7333-be46-b7ae-689e71722bd5";
    public static final String UUID_C_2 = "be940002-7333-be46-b7ae-689e71722bd5";
    public static final String UUID_C_3 = "be940003-7333-be46-b7ae-689e71722bd5";
    public static final String UUID_HID_S = "00001812-0000-1000-8000-00805f9b34fb";
    public static final String UUID_S = "be940000-7333-be46-b7ae-689e71722bd5";

    public static class Dial_Collect {
        public static final int DialBlock = 2;
        public static final int DialDelete = 4;
        public static final int DialInfo = 3;
        public static final int DialSetCurrent = 5;
        public static final int DialSwitch = 0;
    }

    public static class Group {
        public static final int Group_ControlWave = 14;
        public static final int Group_ECGData = 5;
        public static final int Group_ECGList = 4;
        public static final int Group_EndEcgTest = 11;
        public static final int Group_EndSport = 9;
        public static final int Group_Health = 3;
        public static final int Group_HistoryData = 13;
        public static final int Group_OTAUI = 2;
        public static final int Group_PPGData = 7;
        public static final int Group_PPGList = 6;
        public static final int Group_REAL_SPORT = 12;
        public static final int Group_Single = 1;
        public static final int Group_StartEcgTest = 10;
        public static final int Group_StartSport = 8;
    }

    public static class KEY_AppControl {
        public static final int AerobiCcoachMode = 5;
        public static final int AmbientLightMeasurementControl = 30;
        public static final int AmbientTempHumidityMeasurementControl = 32;
        public static final int AppExit = 4;
        public static final int BindDevice = 6;
        public static final int BloodCheck = 3;
        public static final int BloodSugarCheck = 49;
        public static final int BloodTest = 2;
        public static final int EarlyWarning = 38;
        public static final int EcgRealStatus = 20;
        public static final int EffectiveHeart = 37;
        public static final int EffectiveStep = 36;
        public static final int EmoticonIndex = 25;
        public static final int FindDevice = 0;
        public static final int HealthArg = 21;
        public static final int HealthWriteBack = 26;
        public static final int HeartTest = 1;
        public static final int InsuranceNews = 33;
        public static final int LipidCalibration = 56;
        public static final int MobileModel = 35;
        public static final int NotificationPush = 8;
        public static final int PDNumber = 50;
        public static final int PushCallState = 43;
        public static final int PushContacts = 40;
        public static final int PushFemalePhysiological = 42;
        public static final int PushMessage = 39;
        public static final int PushTempAndHumidCalibration = 41;
        public static final int QuerySampleRate = 10;
        public static final int RealData = 9;
        public static final int SendBackgroundLine = 63;
        public static final int SendCardNumber = 52;
        public static final int SendDomain = 62;
        public static final int SendLocationNumber = 51;
        public static final int SendMeasureNumber = 53;
        public static final int SendNotifyToDevice = 61;
        public static final int SendProductInfo = 54;
        public static final int SendToken = 59;
        public static final int SendTokenStatus = 60;
        public static final int SendUUID = 57;
        public static final int SensorSwitchControl = 34;
        public static final int ShutDown = 22;
        public static final int SleepWriteBack = 27;
        public static final int SportMode = 12;
        public static final int StartBloodMeasurement = 46;
        public static final int StartMeasurement = 47;
        public static final int TakePhoto = 14;
        public static final int TempMeasurementControl = 24;
        public static final int TemperatureCorrect = 23;
        public static final int TodayWeather = 18;
        public static final int TomorrowWeather = 19;
        public static final int UnBindDevice = 7;
        public static final int UpgradeReminder = 29;
        public static final int UricAcidCalibration = 55;
        public static final int UserInfoWriteBack = 28;
        public static final int WaveUpload = 11;
        public static final int WritebackData = 44;
    }

    public static class KEY_Collect {
        public static final int CheckData = 32;
        public static final int DeleteWithIndex = 48;
        public static final int DeleteWithTimestamp = 49;
        public static final int FileCount = 5;
        public static final int FileData = 7;
        public static final int FileList = 6;
        public static final int FileSync = 23;
        public static final int FileSyncVerify = 39;
        public static final int GetWithIndex = 1;
        public static final int GetWithTimestamp = 2;
        public static final int QueryNum = 0;
        public static final int SyncData = 16;
    }

    public static class KEY_Collection_Tools {
        public static final int SetValue = 2;
        public static final int Start = 1;
        public static final int Upload = 3;
    }

    public static class KEY_Customize {
        public static final int CGM = 1;
        public static final int Sync_Block_Verify = 128;
        public static final int Sync_Data = 117;
        public static final int Sync_File = 118;
        public static final int WIT = 2;
    }

    public static class KEY_DeviceControl {
        public static final int AlarmData = 15;
        public static final int AnswerAndClosePhone = 2;
        public static final int ConnectOrDisconnect = 7;
        public static final int DrinkingPatterns = 6;
        public static final int EndECG = 11;
        public static final int FindMobile = 0;
        public static final int InflatedBloodMeasureResult = 16;
        public static final int LostReminder = 1;
        public static final int MeasurStatusAndResults = 19;
        public static final int MeasurementResult = 14;
        public static final int PPIData = 18;
        public static final int ReportAlarm = 23;
        public static final int RequestDynamicCode = 21;
        public static final int Rest = 10;
        public static final int SedentaryReminder = 22;
        public static final int Sos = 5;
        public static final int SportMode = 8;
        public static final int SportModeControl = 12;
        public static final int StartMusic = 4;
        public static final int SwitchDial = 13;
        public static final int SyncContacts = 9;
        public static final int TakePhoto = 3;
        public static final int UpgradeResult = 17;
    }

    public static class KEY_Factory {
        public static final int OpenFatory = 9;
    }

    public static class KEY_Get {
        public static final int ALiIOTActivationState = 34;
        public static final int AllRealDataFromDevice = 32;
        public static final int CardInfo = 36;
        public static final int ChipScheme = 27;
        public static final int CurrentAmbientLightIntensity = 18;
        public static final int CurrentAmbientTempAndHumidity = 19;
        public static final int CurrentSystemWorkingMode = 22;
        public static final int DevcieName = 3;
        public static final int DeviceInfo = 0;
        public static final int DeviceLog = 8;
        public static final int DeviceRemindInfo = 31;
        public static final int DeviceScreenInfo = 11;
        public static final int EcgMode = 39;
        public static final int ElectrodeLocation = 10;
        public static final int EventReminderInfo = 26;
        public static final int FunctionState = 4;
        public static final int HeavenEarthAndFiveElement = 16;
        public static final int HistoryOutline = 13;
        public static final int InsuranceRelatedInfo = 23;
        public static final int LaserTreatmentParams = 33;
        public static final int MacAddress = 2;
        public static final int MainTheme = 9;
        public static final int MeasurementFunction = 40;
        public static final int NowStep = 12;
        public static final int PowerStatistics = 37;
        public static final int RealBloodOxygen = 17;
        public static final int RealTemp = 14;
        public static final int ScheduleInfo = 20;
        public static final int ScreenInfo = 15;
        public static final int ScreenParameters = 35;
        public static final int SensorSamplingInfo = 21;
        public static final int SleepStatus = 38;
        public static final int StatusOfManualMode = 25;
        public static final int SupportFunction = 1;
        public static final int UploadConfigurationInfoOfReminder = 24;
        public static final int UserConfig = 7;
    }

    public static class KEY_Health {
        public static final int DeleteAll = 68;
        public static final int DeleteAmbientLight = 72;
        public static final int DeleteBackgroundReminderRecord = 77;
        public static final int DeleteBlood = 67;
        public static final int DeleteBloodOxygen = 69;
        public static final int DeleteBodyData = 78;
        public static final int DeleteComprehensiveMeasureData = 76;
        public static final int DeleteFall = 73;
        public static final int DeleteHealthMonitoring = 74;
        public static final int DeleteHeart = 66;
        public static final int DeleteSleep = 65;
        public static final int DeleteSport = 64;
        public static final int DeleteSportMode = 75;
        public static final int DeleteTemp = 71;
        public static final int DeleteTempAndHumidity = 70;
        public static final int HistoryAll = 9;
        public static final int HistoryAllAck = 24;
        public static final int HistoryAmbientLight = 32;
        public static final int HistoryAmbientLightAck = 40;
        public static final int HistoryBackgroundReminderRecord = 49;
        public static final int HistoryBlock = 128;
        public static final int HistoryBlood = 8;
        public static final int HistoryBloodAck = 23;
        public static final int HistoryBloodOxygen = 26;
        public static final int HistoryBloodOxygenAck = 34;
        public static final int HistoryBodyData = 51;
        public static final int HistoryBodyDataAck = 52;
        public static final int HistoryComprehensiveMeasureData = 47;
        public static final int HistoryComprehensiveMeasureDataAck = 48;
        public static final int HistoryFall = 41;
        public static final int HistoryFallAck = 42;
        public static final int HistoryHealthMonitoring = 43;
        public static final int HistoryHealthMonitoringAck = 44;
        public static final int HistoryHeart = 6;
        public static final int HistoryHeartAck = 21;
        public static final int HistorySleep = 4;
        public static final int HistorySleepAck = 19;
        public static final int HistorySport = 2;
        public static final int HistorySportAck = 17;
        public static final int HistorySportMode = 45;
        public static final int HistorySportModeAck = 46;
        public static final int HistoryTemp = 30;
        public static final int HistoryTempAck = 38;
        public static final int HistoryTempAndHumidity = 28;
        public static final int HistoryTempAndHumidityAck = 36;
    }

    public static class KEY_OTA_DEVICE {
        public static final int FILE_CRC = 2;
        public static final int FILE_DATA = 1;
        public static final int OTA_DOWNLOAD = 0;
    }

    public static class KEY_Real {
        public static final int UploadAmbientlight = 9;
        public static final int UploadBlood = 3;
        public static final int UploadBloodOxygen = 2;
        public static final int UploadBodyData = 16;
        public static final int UploadComprehensive = 10;
        public static final int UploadECG = 5;
        public static final int UploadEventReminder = 12;
        public static final int UploadHeart = 1;
        public static final int UploadInflatedBlood = 14;
        public static final int UploadMulPhotoelectricWaveform = 15;
        public static final int UploadOGA = 13;
        public static final int UploadPPG = 4;
        public static final int UploadRespiratoryRate = 7;
        public static final int UploadRun = 6;
        public static final int UploadSchedule = 11;
        public static final int UploadSensor = 8;
        public static final int UploadSport = 0;
    }

    public static class KEY_Self_Inspection {
        public static final int Self_InspectionCheck = 0;
    }

    public static class KEY_Setting {
        public static final int AccidentMode = 36;
        public static final int AerobicTrain = 17;
        public static final int AirPumpFrequency = 53;
        public static final int Alarm = 1;
        public static final int AmbientLight = 34;
        public static final int AmbientTemperatureAndHumidity = 40;
        public static final int AncsOn = 16;
        public static final int AntiLose = 6;
        public static final int AntiLoseArg = 7;
        public static final int BTName = 23;
        public static final int BloodAlarm = 56;
        public static final int BloodOxygenAlarm = 57;
        public static final int BloodOxygenModeMonitor = 38;
        public static final int BloodRange = 22;
        public static final int BluetoothBroadcastInterval = 44;
        public static final int BluetoothTransmittingPower = 45;
        public static final int BraceletStatusAlert = 37;
        public static final int ConfigInDifWorkingModes = 49;
        public static final int DeviceMac = 52;
        public static final int DisplayBrightness = 20;
        public static final int EmergencyContacts = 72;
        public static final int EventReminder = 47;
        public static final int EventReminderSwitch = 48;
        public static final int ExerciseHeartRateZone = 46;
        public static final int FindPhone = 13;
        public static final int Goal = 2;
        public static final int HRVMonitor = 69;
        public static final int HandWear = 8;
        public static final int HeartAlarm = 11;
        public static final int HeartMonitor = 12;
        public static final int InsuranceSwitch = 50;
        public static final int Language = 18;
        public static final int LaserTreatmentParams = 59;
        public static final int LatitudeAndLongitude = 55;
        public static final int LongSite = 5;
        public static final int LunchDoNotDisturbMode = 51;
        public static final int MainTheme = 25;
        public static final int NotDisturb = 15;
        public static final int Notification = 10;
        public static final int PPGCollect = 27;
        public static final int PhoneOS = 9;
        public static final int RaiseScreen = 19;
        public static final int RegularReminder = 61;
        public static final int RespiratoryRateAlarm = 62;
        public static final int RestoreFactory = 14;
        public static final int ScheduleModification = 39;
        public static final int ScheduleSwitch = 41;
        public static final int ScreenTime = 33;
        public static final int SensorRate = 24;
        public static final int Skin = 21;
        public static final int SleepRemind = 26;
        public static final int SosSwitch = 54;
        public static final int SportHeartAlarm = 70;
        public static final int StepCountingStateTime = 42;
        public static final int StudentData = 30;
        public static final int TemperatureAlarm = 31;
        public static final int TemperatureMonitor = 32;
        public static final int Time = 0;
        public static final int Unit = 4;
        public static final int UploadReminder = 43;
        public static final int UserInfo = 3;
        public static final int VibrationIntensity = 60;
        public static final int VibrationTime = 58;
        public static final int WorkingMode = 35;
    }

    public static class KEY_Test_Tool {
        public static final int Gsensor = 4;
    }

    public static class KEY_UI {
        public static final int UI_GetFileBreak = 0;
        public static final int UI_SyncBlock = 2;
        public static final int UI_SyncBlockCheck = 3;
        public static final int UI_SyncFileInfo = 1;
    }
}
