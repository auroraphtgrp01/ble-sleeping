package com.yucheng.ycbtsdk;

/* loaded from: classes4.dex */
public class Constants {

    public static class BLEState {
        public static final int CharacteristicDiscovered = 8;
        public static final int CharacteristicNotification = 9;
        public static final int Connected = 6;
        public static final int Connecting = 5;
        public static final int Disconnect = 3;
        public static final int Disconnecting = 4;
        public static final int NotOpen = 2;
        public static final int ReadWriteOK = 10;
        public static final int ServicesDiscovered = 7;
        public static final int TimeOut = 1;
    }

    public static class CODE {
        public static final int Code_Failed = 1;
        public static final int Code_OK = 0;
        public static final int Code_Scan_Failed = 3;
        public static final int Code_TimeOut = 2;
    }

    public class CardType {
        public static final int Facebook = 2;
        public static final int Instgram = 5;
        public static final int Lock_Code = 243;
        public static final int QQ = 1;
        public static final int Sn = 240;
        public static final int Sn_Dynamic = 242;
        public static final int Sn_Static = 241;
        public static final int Twitter = 3;
        public static final int Unlock_Code = 244;
        public static final int Whatsapp = 4;
        public static final int wechat = 0;

        public CardType() {
        }
    }

    public class Common {
        public static final int BloodKetone = 7;
        public static final int BloodLipids = 9;
        public static final int BloodOxygen = 2;
        public static final int BloodPressure = 1;
        public static final int BloodSugar = 5;
        public static final int BodyTemperature = 4;
        public static final int EDA = 8;
        public static final int HRV = 10;
        public static final int HeartRateAlarm = 0;
        public static final int OxygenIntake = 13;
        public static final int PPG = 11;
        public static final int Pressure = 12;
        public static final int RespiratoryRate = 3;
        public static final int UricAcid = 6;

        public Common() {
        }
    }

    public static class DATATYPE {
        public static final int ALIDATA = 48059;
        public static final int AppAmbientLightMeasurementControl = 798;
        public static final int AppAmbientTempHumidityMeasurementControl = 800;
        public static final int AppBloodCalibration = 771;
        public static final int AppBloodSugarCalibration = 817;
        public static final int AppBloodSwitch = 770;
        public static final int AppControlReal = 777;
        public static final int AppControlTakePhoto = 782;
        public static final int AppControlWave = 779;
        public static final int AppECGPPGStatus = 788;
        public static final int AppEarlyWarning = 806;
        public static final int AppEffectiveHeart = 805;
        public static final int AppEffectiveStep = 804;
        public static final int AppEmoticonIndex = 793;
        public static final int AppFindDevice = 768;
        public static final int AppHealthArg = 789;
        public static final int AppHealthWriteBack = 794;
        public static final int AppHeartSwitch = 769;
        public static final int AppInsuranceNews = 801;
        public static final int AppLipidCalibration = 824;
        public static final int AppMessageControl = 776;
        public static final int AppMobileModel = 803;
        public static final int AppPDNumber = 818;
        public static final int AppPushCallState = 811;
        public static final int AppPushContacts = 808;
        public static final int AppPushFemalePhysiological = 810;
        public static final int AppPushMessage = 807;
        public static final int AppPushTempAndHumidCalibration = 809;
        public static final int AppRunMode = 780;
        public static final int AppSendBackgroundLine = 831;
        public static final int AppSendCardNumber = 820;
        public static final int AppSendDomain = 830;
        public static final int AppSendLocationNumber = 819;
        public static final int AppSendMeasureNumber = 821;
        public static final int AppSendNotifyToDevice = 829;
        public static final int AppSendProductInfo = 822;
        public static final int AppSendToken = 827;
        public static final int AppSendTokenStatus = 828;
        public static final int AppSendUUID = 825;
        public static final int AppSensorSwitchControl = 802;
        public static final int AppShutDown = 790;
        public static final int AppSleepWriteBack = 795;
        public static final int AppStartBloodMeasurement = 814;
        public static final int AppStartMeasurement = 815;
        public static final int AppTemperatureCode = 799;
        public static final int AppTemperatureCorrect = 791;
        public static final int AppTemperatureMeasure = 792;
        public static final int AppTodayWeather = 786;
        public static final int AppTomorrowWeather = 787;
        public static final int AppUpgradeReminder = 797;
        public static final int AppUricAcidCalibration = 823;
        public static final int AppUserInfoWriteBack = 796;
        public static final int AppWritebackData = 812;
        public static final int Collect_DeleteIndex = 1840;
        public static final int Collect_DeleteTimestamp = 1841;
        public static final int Collect_File_Content = 1799;
        public static final int Collect_File_Count = 1797;
        public static final int Collect_File_List = 1798;
        public static final int Collect_File_Sync = 1815;
        public static final int Collect_File_Sync_Verify = 1831;
        public static final int Collect_GetWithIndex = 1793;
        public static final int Collect_GetWithTimestamp = 1794;
        public static final int Collect_QueryNum = 1792;
        public static final int Collect_SyncCheck = 1824;
        public static final int Collect_SyncData = 1808;
        public static final int CollectionUpload = 4867;
        public static final int Customize_Block_Verify = 3456;
        public static final int Customize_CGM = 3329;
        public static final int Customize_Data_Sync = 3445;
        public static final int Customize_File_Sync = 3446;
        public static final int Customize_Intelligent_Functions = 3330;
        public static final int DataSetting = 3587;
        public static final int DeviceAlarmData = 1039;
        public static final int DeviceAnswerAndClosePhone = 1026;
        public static final int DeviceConnectOrDisconnect = 1031;
        public static final int DeviceDrinkingPatterns = 1030;
        public static final int DeviceEndECG = 1035;
        public static final int DeviceFindMobile = 1024;
        public static final int DeviceInflatedBloodMeasureResult = 1040;
        public static final int DeviceLostReminder = 1025;
        public static final int DeviceMeasurStatusAndResults = 1043;
        public static final int DeviceMeasurementResult = 1038;
        public static final int DevicePPIData = 1042;
        public static final int DeviceReportAlarm = 1047;
        public static final int DeviceRequestDynamicCode = 1045;
        public static final int DeviceRest = 1034;
        public static final int DeviceSedentaryReminder = 1046;
        public static final int DeviceSos = 1029;
        public static final int DeviceSportMode = 1032;
        public static final int DeviceSportModeControl = 1036;
        public static final int DeviceStartMusic = 1028;
        public static final int DeviceSwitchDial = 1037;
        public static final int DeviceSyncContacts = 1033;
        public static final int DeviceTakePhoto = 1027;
        public static final int DeviceUpgradeResult = 1041;
        public static final int ElectricGuantityMonitoring = 3589;
        public static final int GetALiIOTActivationState = 546;
        public static final int GetAllRealDataFromDevice = 544;
        public static final int GetCardInfo = 548;
        public static final int GetChipScheme = 539;
        public static final int GetCurrentAmbientLightIntensity = 530;
        public static final int GetCurrentAmbientTempAndHumidity = 531;
        public static final int GetCurrentSystemWorkingMode = 534;
        public static final int GetDeviceInfo = 512;
        public static final int GetDeviceLog = 520;
        public static final int GetDeviceMac = 514;
        public static final int GetDeviceName = 515;
        public static final int GetDeviceRemindInfo = 543;
        public static final int GetDeviceScreenInfo = 523;
        public static final int GetDeviceSupportFunction = 513;
        public static final int GetDeviceUserConfig = 519;
        public static final int GetEcgMode = 551;
        public static final int GetElectrodeLocation = 522;
        public static final int GetEventReminderInfo = 538;
        public static final int GetHeavenEarthAndFiveElement = 528;
        public static final int GetHistoryOutline = 525;
        public static final int GetInsuranceRelatedInfo = 535;
        public static final int GetLaserTreatmentParams = 545;
        public static final int GetMeasurementFunction = 552;
        public static final int GetNowStep = 524;
        public static final int GetPowerStatistics = 549;
        public static final int GetRealBloodOxygen = 529;
        public static final int GetRealTemp = 526;
        public static final int GetScheduleInfo = 532;
        public static final int GetScreenInfo = 527;
        public static final int GetScreenParameters = 547;
        public static final int GetSensorSamplingInfo = 533;
        public static final int GetSleepStatus = 550;
        public static final int GetStatusOfManualMode = 537;
        public static final int GetThemeInfo = 521;
        public static final int GetUploadConfigurationInfoOfReminder = 536;
        public static final int Gsensor = 3588;
        public static final int Health_DeleteAll = 1348;
        public static final int Health_DeleteAmbientLight = 1352;
        public static final int Health_DeleteBackgroundReminderRecord = 1357;
        public static final int Health_DeleteBlood = 1347;
        public static final int Health_DeleteBloodOxygen = 1349;
        public static final int Health_DeleteBodyData = 1358;
        public static final int Health_DeleteComprehensiveMeasureData = 1356;
        public static final int Health_DeleteFall = 1353;
        public static final int Health_DeleteHealthMonitoring = 1354;
        public static final int Health_DeleteHeart = 1346;
        public static final int Health_DeleteSleep = 1345;
        public static final int Health_DeleteSport = 1344;
        public static final int Health_DeleteSportMode = 1355;
        public static final int Health_DeleteTemp = 1351;
        public static final int Health_DeleteTempAndHumidity = 1350;
        public static final int Health_HistoryAll = 1289;
        public static final int Health_HistoryAmbientLight = 1312;
        public static final int Health_HistoryBlock = 1408;
        public static final int Health_HistoryBlood = 1288;
        public static final int Health_HistoryBloodOxygen = 1306;
        public static final int Health_HistoryComprehensiveMeasureData = 1327;
        public static final int Health_HistoryFall = 1321;
        public static final int Health_HistoryHealthMonitoring = 1323;
        public static final int Health_HistoryHeart = 1286;
        public static final int Health_HistorySleep = 1284;
        public static final int Health_HistorySport = 1282;
        public static final int Health_HistorySportMode = 1325;
        public static final int Health_HistoryTemp = 1310;
        public static final int Health_HistoryTempAndHumidity = 1308;
        public static final int Health_History_Body_Data = 1331;
        public static final int JLDATA = 43690;
        public static final int JLOTADATA = 52428;
        public static final int OTADownload = 2560;
        public static final int OTAProgress = 39178;
        public static final int OneKeyBackground = 3586;
        public static final int OpenFactory = 2057;
        public static final int OtaBlock = 2562;
        public static final int OtaSend = 2561;
        public static final int OtaUI_GetFileBreak = 32256;
        public static final int OtaUI_SyncBlock = 32258;
        public static final int OtaUI_SyncBlockCheck = 32259;
        public static final int OtaUI_SyncFileInfo = 32257;
        public static final int PowerMonitoringDataUploadFormat = 3445;
        public static final int PrefabWatchDialDownload = 2310;
        public static final int Real_UploadAmbientlight = 1545;
        public static final int Real_UploadBlood = 1539;
        public static final int Real_UploadBloodOxygen = 1538;
        public static final int Real_UploadBodyData = 1552;
        public static final int Real_UploadComprehensive = 1546;
        public static final int Real_UploadECG = 1541;
        public static final int Real_UploadECGHrv = 1776;
        public static final int Real_UploadECGRR = 1777;
        public static final int Real_UploadEventReminder = 1548;
        public static final int Real_UploadHeart = 1537;
        public static final int Real_UploadInflatedBlood = 1550;
        public static final int Real_UploadMulPhotoelectricWaveform = 1551;
        public static final int Real_UploadOGA = 1549;
        public static final int Real_UploadPPG = 1540;
        public static final int Real_UploadRespiratoryRate = 1543;
        public static final int Real_UploadRun = 1542;
        public static final int Real_UploadSchedule = 1547;
        public static final int Real_UploadSensor = 1544;
        public static final int Real_UploadSport = 1536;
        public static final int SelfInspection = 3072;
        public static final int SetTheBenchmarkDeviceValue = 4866;
        public static final int SettingAccidentMode = 292;
        public static final int SettingAirPumpFrequency = 309;
        public static final int SettingAlarm = 257;
        public static final int SettingAmbientLight = 290;
        public static final int SettingAmbientTemperatureAndHumidity = 296;
        public static final int SettingAntiLose = 262;
        public static final int SettingAppSystem = 265;
        public static final int SettingAutomaticMeasurementTime = 320;
        public static final int SettingBloodAlarm = 312;
        public static final int SettingBloodOxygenAlarm = 313;
        public static final int SettingBloodOxygenModeMonitor = 294;
        public static final int SettingBloodRange = 278;
        public static final int SettingBloodSugarAlarm = 319;
        public static final int SettingBluetoothBroadcastInterval = 300;
        public static final int SettingBluetoothTransmittingPower = 301;
        public static final int SettingBraceletStatusAlert = 293;
        public static final int SettingConfigInDifWorkingModes = 305;
        public static final int SettingDataCollect = 283;
        public static final int SettingDeviceMac = 308;
        public static final int SettingDeviceName = 279;
        public static final int SettingDisplayBrightness = 276;
        public static final int SettingEmergencyContacts = 328;
        public static final int SettingEventReminder = 303;
        public static final int SettingEventReminderSwitch = 304;
        public static final int SettingExerciseHeartRateZone = 302;
        public static final int SettingFindPhone = 269;
        public static final int SettingGoal = 258;
        public static final int SettingHRVMonitor = 325;
        public static final int SettingHandWear = 264;
        public static final int SettingHeartAlarm = 267;
        public static final int SettingHeartMonitor = 268;
        public static final int SettingInsuranceSwitch = 306;
        public static final int SettingLanguage = 274;
        public static final int SettingLaserTreatmentParams = 315;
        public static final int SettingLatitudeAndLongitude = 311;
        public static final int SettingLongsite = 261;
        public static final int SettingLunchDoNotDisturbMode = 307;
        public static final int SettingMainTheme = 281;
        public static final int SettingMeasurementFunction = 329;
        public static final int SettingNotDisturb = 271;
        public static final int SettingNotify = 266;
        public static final int SettingRaiseScreen = 275;
        public static final int SettingRegularReminder = 317;
        public static final int SettingRespiratoryRateAlarm = 318;
        public static final int SettingRestoreFactory = 270;
        public static final int SettingRingSizeAndColor = 323;
        public static final int SettingScheduleModification = 295;
        public static final int SettingScheduleSwitch = 297;
        public static final int SettingScreenTime = 289;
        public static final int SettingSettingCustomDial = 321;
        public static final int SettingSkin = 277;
        public static final int SettingSleepRemind = 282;
        public static final int SettingSosSwitch = 310;
        public static final int SettingSportHeartAlarm = 326;
        public static final int SettingStepCountingStateTime = 298;
        public static final int SettingStudentData = 286;
        public static final int SettingTemperatureAlarm = 287;
        public static final int SettingTemperatureMonitor = 288;
        public static final int SettingTime = 256;
        public static final int SettingTimeZone = 324;
        public static final int SettingUnit = 260;
        public static final int SettingUploadReminder = 299;
        public static final int SettingUserInfo = 259;
        public static final int SettingVibrationIntensity = 316;
        public static final int SettingVibrationTime = 314;
        public static final int SettingWorkingMode = 291;
        public static final int SpecificInformationPush = 816;
        public static final int StartCollection = 4865;
        public static final int SwitchMachineLogoDownload = 2311;
        public static final int VibrationMotorControl = 3590;
        public static final int WatchDialBlook = 2306;
        public static final int WatchDialDelete = 2308;
        public static final int WatchDialDownload = 2304;
        public static final int WatchDialInfo = 2307;
        public static final int WatchDialProgress = 39168;
        public static final int WatchDialSend = 2305;
        public static final int WatchDialSetCurrent = 2309;
        public static final int WatchUIUpgradeBlook = 32259;
        public static final int WatchUIUpgradeDown = 32257;
        public static final int WatchUIUpgradeInfo = 32256;
        public static final int WatchUIUpgradeSend = 32258;
        public static final int health_BackgroundReminderRecord = 1329;
    }

    public class DataSet {
        public static final int Measurement = 1;
        public static final int MoveMent = 2;
        public static final int Sleep = 3;

        public DataSet() {
        }
    }

    public class DeviceType {
        public static final int Ring = 1;
        public static final int Watch = 0;

        public DeviceType() {
        }
    }

    public class DisplayBrightness {
        public static final int Auto = 3;
        public static final int High = 2;
        public static final int Higher = 5;
        public static final int Low = 0;
        public static final int Lower = 4;
        public static final int Middle = 1;

        public DisplayBrightness() {
        }
    }

    public class ElectricMonitoringType {
        public static final int ChargeAcquisitionCurve = 3;
        public static final int GetKeyPointVoltage = 4;
        public static final int OnOff = 1;
        public static final int SetPower = 2;

        public ElectricMonitoringType() {
        }
    }

    public class FunctionConstant {
        public static final String ALARMCOUNT = "alarmCount";
        public static final String DEVICETYPE = "deviceType";
        public static final String ISFLIPDIALIMAGE = "isFlipDialImage";
        public static final String ISHASAEROBICS = "isHasAerobics";
        public static final String ISHASALIIOT = "isHasALiIOT";
        public static final String ISHASANTILOST = "isHasAntiLost";
        public static final String ISHASAPPOINT = "isHasAppoint";
        public static final String ISHASBADMINTON = "isHasBadminton";
        public static final String ISHASBASKETBALL = "isHasBasketball";
        public static final String ISHASBLOOD = "isHasBlood";
        public static final String ISHASBLOODALARM = "isHasBloodAlarm";
        public static final String ISHASBLOODKETONEMEASUREMENT = "isHasBloodKetoneMeasurement";
        public static final String ISHASBLOODLEVEL = "isHasBloodLevel";
        public static final String ISHASBLOODOXYGEN = "isHasBloodOxygen";
        public static final String ISHASBLOODOXYGENALARM = "isHasBloodOxygenAlarm";
        public static final String ISHASBLOODPRESSURECALIBRATION = "isHasBloodPressureCalibration";
        public static final String ISHASBLOODSUGAR = "isHasBloodSugar";
        public static final String ISHASBUSINESSCARD = "isHasBusinessCard";
        public static final String ISHASCALLPHONE = "isHasCallPhone";
        public static final String ISHASCONTACTS = "isHasContacts";
        public static final String ISHASCREATEBOND = "isHasCreateBond";
        public static final String ISHASCUSTOM = "isHasCustom";
        public static final String ISHASCUSTOMDIAL = "isHasCustomDial";
        public static final String ISHASCVRR = "isHasCVRR";
        public static final String ISHASDANCE = "isHasDance";
        public static final String ISHASDIAL = "isHasDial";
        public static final String ISHASDRINKWATERREMINDER = "isHasDrinkWaterReminder";
        public static final String ISHASECGDIAGNOSIS = "isHasECGDiagnosis";
        public static final String ISHASECGHISTORYUPLOAD = "isHasEcgHistoryUpload";
        public static final String ISHASECGREALUPLOAD = "isHasEcgRealUpload";
        public static final String ISHASECGRIGHTELECTRODE = "isHasECGRightElectrode";
        public static final String ISHASELLIPTICALMACHINE = "isHasEllipticalMachine";
        public static final String ISHASEMAIL = "isHasEmail";
        public static final String ISHASENCRYPTION = "isHasEncryption";
        public static final String ISHASFACEBOOK = "isHasFaceBook";
        public static final String ISHASFACTORYSETTING = "isHasFactorySetting";
        public static final String ISHASFEMALEPHYSIOLOGICALCYCLE = "isHasFemalePhysiologicalCycle";
        public static final String ISHASFINDDEVICE = "isHasFindDevice";
        public static final String ISHASFINDPHONE = "isHasFindPhone";
        public static final String ISHASFIRMWAREUPDATE = "isHasFirmwareUpdate";
        public static final String ISHASFITNESS = "isHasFitness";
        public static final String ISHASFOOTBALL = "isHasFootBall";
        public static final String ISHASGETUP = "isHasGetUp";
        public static final String ISHASGOLF = "isHasGolf";
        public static final String ISHASHEARTALARM = "isHasHeartAlarm";
        public static final String ISHASHEARTRATE = "isHasHeartRate";
        public static final String ISHASHRV = "isHasHrv";
        public static final String ISHASIMPRECISEBLOODFAT = "isHasImpreciseBloodFat";
        public static final String ISHASINACCURATEECG = "isHasInaccurateECG";
        public static final String ISHASINDOORRIDING = "isHasIndoorRiding";
        public static final String ISHASINDOORRUNING = "isHasIndoorRuning";
        public static final String ISHASINDOORWALKING = "isHasIndoorWalking";
        public static final String ISHASINFLATED = "isHasInflated";
        public static final String ISHASINFORMATION = "isHasInformation";
        public static final String ISHASINSTAGRAM = "isHasInstagram";
        public static final String ISHASJUMPING = "isHasJumping";
        public static final String ISHASKAKAOTALKNOTIFY = "isHasKakaoTalkNotify";
        public static final String ISHASKAYAK = "isHasKayak";
        public static final String ISHASKINDSINFORMATIONPUSH = "isHasKindsInformationPush";
        public static final String ISHASLIFTBRIGHT = "isHasLiftBright";
        public static final String ISHASLINE = "isHasLine";
        public static final String ISHASLINKEDIN = "isHasLinkedIn";
        public static final String ISHASLONGSITTING = "isHasLongSitting";
        public static final String ISHASMANUALTAKEPHOTO = "isHasManualTakePhoto";
        public static final String ISHASMANYLANGUAGE = "isHasManyLanguage";
        public static final String ISHASMEETING = "isHasMeeting";
        public static final String ISHASMESSAGE = "isHasMessage";
        public static final String ISHASMESSENGER = "isHasMessenger";
        public static final String ISHASMORESPORT = "isHasMoreSport";
        public static final String ISHASMOUNTAINCLIMBING = "isHasMountainClimbing";
        public static final String ISHASMUSIC = "isHasMusic";
        public static final String ISHASNOTITOGGLE = "isHasNotiToggle";
        public static final String ISHASONFOOT = "isHasOnFoot";
        public static final String ISHASOTHERMESSENGER = "isHasOtherMessenger";
        public static final String ISHASOTHERSPORTS = "isHasOtherSports";
        public static final String ISHASOTHRENOTIFY = "isHasOtherNotify";
        public static final String ISHASOUTDOORRUNING = "isHasOutdoorRuning";
        public static final String ISHASOUTDOORWALKING = "isHasOutdoorWalking";
        public static final String ISHASPARTY = "isHasParty";
        public static final String ISHASPAUSEEXERCISE = "isHasPauseExercise";
        public static final String ISHASPHONESUPPORT = "isHasPhoneSupport";
        public static final String ISHASPINGPONG = "isHasPingPong";
        public static final String ISHASQQ = "isHasQQ";
        public static final String ISHASREALDATA = "isHasRealData";
        public static final String ISHASREALEXERCISEDATA = "isHasRealExerciseData";
        public static final String ISHASREALTIMEMONITORINGMODE = "isHasRealtimeMonitoringMode";
        public static final String ISHASRESPIRATORYRATE = "isHasRespiratoryRate";
        public static final String ISHASRESPIRATORYRATEALARM = "isHasRespiratoryRateAlarm";
        public static final String ISHASRIDING = "isHasRiding";
        public static final String ISHASROCKCLIMBING = "isHasRockClimbing";
        public static final String ISHASROLLERSKATING = "isHasRollerSkating";
        public static final String ISHASROPESKIPPING = "isHasRopeSkipping";
        public static final String ISHASROWINGMACHINE = "isHasRowingMachine";
        public static final String ISHASRUNNING = "isHasRunning";
        public static final String ISHASSEARCHAROUND = "isHasSearchAround";
        public static final String ISHASSETINFO = "isHasSetInfo";
        public static final String ISHASSETSCREENTIME = "isHasSetScreenTime";
        public static final String ISHASSHAKETAKEPHOTO = "isHasShakeTakePhoto";
        public static final String ISHASSINA = "isHasSina";
        public static final String ISHASSITUPS = "isHasSitUps";
        public static final String ISHASSKINCOLOR = "isHasSkinColor";
        public static final String ISHASSKYPE = "isHasSkype";
        public static final String ISHASSLEEP = "isHasSleep";
        public static final String ISHASSNAPCHAT = "isHasSnapChat";
        public static final String ISHASSOS = "isHasSos";
        public static final String ISHASSTEPCOUNT = "isHasStepCount";
        public static final String ISHASSTEPPER = "isHasStepper";
        public static final String ISHASSWIMMING = "isHasSwimming";
        public static final String ISHASTAKEEXERCISE = "isHasTakeExercise";
        public static final String ISHASTAKEPILLS = "isHasTakePills";
        public static final String ISHASTAKESLEEP = "isHasTakeSleep";
        public static final String ISHASTEMP = "isHasTemp";
        public static final String ISHASTEMPALARM = "isHasTempAlarm";
        public static final String ISHASTEMPAXILLARYTEST = "isHasTempAxillaryTest";
        public static final String ISHASTEMPCALIBRATION = "isHasTempCalibration";
        public static final String ISHASTENNIS = "isHasTennis";
        public static final String ISHASTESTBLOOD = "isHasTestBlood";
        public static final String ISHASTESTRESPIRATIONRATE = "isHasTestRespirationRate";
        public static final String ISHASTESTSPO2 = "isHasTestSpo2";
        public static final String ISHASTESTTEMP = "isHasTestTemp";
        public static final String ISHASTHEME = "isHasTheme";
        public static final String ISHASTIKTOKNOTIFY = "isHasTikTokNotify";
        public static final String ISHASTODAYWEATHER = "isHasTodayWeather";
        public static final String ISHASTOMORROWWEATHER = "isHasTomorrowWeather";
        public static final String ISHASTWITTER = "isHasTwitter";
        public static final String ISHASUPLOADINFLATEBLOOD = "isHasUploadInflateBlood";
        public static final String ISHASURICACIDMEASUREMENT = "isHasUricAcidMeasurement";
        public static final String ISHASVIBERNOTIFY = "isHasViberNotify";
        public static final String ISHASVIBRATIONINTENSITY = "isHasVibrationIntensity";
        public static final String ISHASVOLLEYBALL = "isHasVolleyball";
        public static final String ISHASWALKING = "isHasWalking";
        public static final String ISHASWATCHSCREENBRIGHTNESS = "isHasWatchScreenBrightness";
        public static final String ISHASWECHAT = "isHasWeChat";
        public static final String ISHASWECHATSPORT = "isHasWeChatSport";
        public static final String ISHASWEIGHTTRAINING = "isHasWeightTraining";
        public static final String ISHASWHATSAPP = "isHasWhatsAPP";
        public static final String ISHASYOGA = "isHasYoga";
        public static final String ISHASZOOMNOTIFY = "isHasZoomNotify";
        public static final String ISHATESTHEART = "isHasTestHeart";
        public static final String IS_HAS_BATTERY_INFO_UPLOAD = "isHasBatteryInfoUpload";
        public static final String IS_HAS_BLOODSUGAR_MEASUREMENT = "isHasBloodSugarMeasurement";
        public static final String IS_HAS_DEVICE_SPEC = "isHasDeviceSpec";
        public static final String IS_HAS_HRV_MEASUREMENT = "isHasHrvMeasurement";
        public static final String IS_HAS_INDEPENDENT_AUTOMATIC_TIME_MEASUREMENT = "isHasIndependentAutomaticTimeMeasurement";
        public static final String IS_HAS_LOCAL_SPORT_DATA = "isHasLocalSportData";
        public static final String IS_HAS_LOGO = "isHasLOGO";
        public static final String IS_HAS_MAXIMAL_OXYGEN_INTAKE = "isHasMaximalOxygenIntake";
        public static final String IS_HAS_MeasurementFunction = "IS_HAS_MeasurementFunction";
        public static final String IS_HAS_OXYGENINTAKE_MEASUREMENT = "isHasOxygenintakeMeasurement";
        public static final String IS_HAS_PHYSIOTHERAPY = "isHasPhysiotherapy";
        public static final String IS_HAS_PRECISION_BLOOD_GLUCOSE = "isHasPrecisionBloodGlucose";
        public static final String IS_HAS_PRECISION_BLOOD_KETONE = "isHasPrecisionBloodKetone";
        public static final String IS_HAS_PRECISION_LIPIDS = "isHasPrecisionLipids";
        public static final String IS_HAS_PRECISION_URIC_ACID = "isHasPrecisionUricAcid";
        public static final String IS_HAS_PRESSURE = "isHasPressure";
        public static final String IS_HAS_PRESSURE_MEASUREMENT = "isHasPressureMeasurement";
        public static final String IS_HAS_RECORDING_FILE = "isHasRecordingFile";
        public static final String IS_HAS_SLEEP_REMIND = "isHasSleepRemind";
        public static final String IS_HAS_Sporadic_Naps = "isHasSporadicNaps";
        public static final String IS_MOTION_DELAY_DISCONNECT = "isMotionDelayDisconnect";
        public static final String WATCHSCREENBRIGHTNESS = "watchScreenBrightness";

        public FunctionConstant() {
        }
    }

    public class FunctionType {
        public static final int BloodFat = 2;
        public static final int BloodSugar = 0;
        public static final int UricAcid = 1;

        public FunctionType() {
        }
    }

    public class HandWear {
        public static final int Left = 0;
        public static final int Right = 1;

        public HandWear() {
        }
    }

    public class IntelligentFunctions {
        public static final int Music = 2;
        public static final int Read = 3;
        public static final int SOS = 5;
        public static final int Short_Video = 1;
        public static final int Slideshow = 6;
        public static final int Take_Photos_Videos = 4;

        public IntelligentFunctions() {
        }
    }

    public class Movement {
        public static final int Calorie = 2;
        public static final int Mileage = 3;
        public static final int MovingObject = 4;
        public static final int StepNumber = 1;

        public Movement() {
        }
    }

    public class OneKeyBackground {
        public static final int BluetoothNotConnected = 100;
        public static final int Charging = 194;
        public static final int DrinkWaterReminder = 103;
        public static final int FullyCharged = 195;
        public static final int GoalAchievement = 98;
        public static final int LookDevice = 102;
        public static final int LookPhone = 101;
        public static final int LostReminder = 99;
        public static final int LowVoltage = 193;
        public static final int SedentaryReminder = 97;
        public static final int TakeMedicineReminder = 104;

        public OneKeyBackground() {
        }
    }

    public class PauseTime {
        public static final int Time10s = 1;
        public static final int Time15s = 2;
        public static final int Time30s = 3;
        public static final int Time5s = 0;

        public PauseTime() {
        }
    }

    public class Platform {
        public static final int JL_AC632N = 4;
        public static final int JL_AC707N = 5;
        public static final int JieLi = 3;
        public static final int Nordic = 0;
        public static final int Realtek = 1;
        public static final int Realtek2 = 2;

        public Platform() {
        }
    }

    public class PushMessageIndex {
        public static final int EMAILINDEX = 2;
        public static final int FACEBOOKINDEX = 6;
        public static final int INSTAGRAMINDEX = 11;
        public static final int KAKAOTALKINDEX = 18;
        public static final int LINEINDEX = 13;
        public static final int LINKED_ININDEX = 10;
        public static final int MESSENGERINDEX = 8;
        public static final int OTHERINDEX = 20;
        public static final int PHONEINDEX = 0;
        public static final int QQINDEX = 4;
        public static final int SINAINDEX = 5;
        public static final int SKYPEINDEX = 12;
        public static final int SMSINDEX = 1;
        public static final int SNAPCHATINDEX = 14;
        public static final int TELEGRAMINDEX = 15;
        public static final int TIKTOKINDEX = 17;
        public static final int TWITTERINDEX = 7;
        public static final int VIBERINDEX = 19;
        public static final int WECHATINDEX = 3;
        public static final int WHATSAPPINDEX = 9;
        public static final int ZOOMINDEX = 16;

        public PushMessageIndex() {
        }
    }

    public class SharedKey {
        public static final String Dynamic_Current = "Dynamic_Current";
        public static final String Dynamic_CurrentStr = "Dynamic_CurrentStr";
        public static final String Dynamic_End = "Dynamic_End";
        public static final String Dynamic_EndStr = "Dynamic_EndStr";
        public static final String Dynamic_MacStr = "Dynamic_MacStr";
        public static final String Dynamic_Start = "Dynamic_Start";
        public static final String Dynamic_StartStr = "Dynamic_StartStr";
        public static final String Function_Str = "Function_Str";
        public static final String Is_Create_Bond = "Is_Create_Bond";
        public static final String Sn_Current = "Sn_Current";
        public static final String Sn_CurrentStr = "Sn_CurrentStr";
        public static final String Sn_End = "Sn_End";
        public static final String Sn_EndStr = "Sn_EndStr";
        public static final String Sn_Start = "Sn_Start";
        public static final String Sn_StartStr = "Sn_StartStr";

        public SharedKey() {
        }
    }

    public class SkinColor {
        public static final int SKIN_BLACK = 5;
        public static final int SKIN_BROWN = 3;
        public static final int SKIN_BROWNNESS = 4;
        public static final int SKIN_WHITE = 0;
        public static final int SKIN_WHITE_BETWEEN_YELLOW = 1;
        public static final int SKIN_YELLOW = 2;

        public SkinColor() {
        }
    }

    public class Sleep {
        public static final int DeepSleep = 1;
        public static final int EyeMovement = 3;
        public static final int LightSleep = 2;

        public Sleep() {
        }
    }

    public class SleepType {
        public static final int awake = 244;
        public static final int deepSleep = 241;
        public static final int lightSleep = 242;
        public static final int naps = 245;
        public static final int rem = 243;
        public static final int unknow = -1;

        public SleepType() {
        }
    }

    public class SportState {
        public static final int Continue = 3;
        public static final int Pause = 2;
        public static final int Start = 1;
        public static final int Stop = 0;

        public SportState() {
        }
    }

    public class SportType {
        public static final int AEROBICS = 36;
        public static final int BADMINTON = 9;
        public static final int BASKETBALL = 7;
        public static final int DANCE = 34;
        public static final int ELLIPTICAL_MACHINE = 33;
        public static final int FITNESS = 4;
        public static final int FOOTBALL = 10;
        public static final int FREE_MODE = 13;
        public static final int GOLF = 32;
        public static final int INDOOR_CYCLING = 19;
        public static final int KAYAK = 29;
        public static final int LEAPING_MOTION = 24;
        public static final int MOUNTAINEERING = 11;
        public static final int ONFOOT = 27;
        public static final int OTHERSPORTS = 37;
        public static final int PING_PONG = 12;
        public static final int REAL_TIME_MODE = 22;
        public static final int RESERVED = 0;
        public static final int RIDE = 3;
        public static final int ROCK_CLIMBING = 35;
        public static final int ROLLER_SKATING = 30;
        public static final int ROWING_MACHINE = 21;
        public static final int RUN = 1;
        public static final int RUN_INDOORS = 14;
        public static final int RUN_OUTSIDE = 15;
        public static final int SCRAP = 5;
        public static final int SIT_UPS = 23;
        public static final int SKIPPING_ROPE = 6;
        public static final int STEPPER = 20;
        public static final int SWIMMING = 2;
        public static final int TENNIS = 31;
        public static final int VOLLEYBALL = 28;
        public static final int WALKING = 8;
        public static final int WALK_AND_RUN = 18;
        public static final int WALK_INDOOR = 17;
        public static final int WALK_OUTDOOR = 16;
        public static final int WEIGHT_TRAINING = 25;
        public static final int YOGA = 26;

        public SportType() {
        }
    }
}
