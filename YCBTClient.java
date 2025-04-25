package com.yucheng.ycbtsdk;

import android.bluetooth.BluetoothGatt;
import android.content.Context;
import android.text.TextUtils;
import com.alibaba.fastjson2.JSONB;
import com.facebook.internal.ServerProtocol;
import com.facebook.internal.security.CertificateUtil;
import com.google.firebase.crashlytics.buildtools.reloc.org.apache.commons.cli.HelpFormatter;
import com.google.firebase.crashlytics.buildtools.reloc.org.apache.http.cookie.ClientCookie;
import com.google.gson.Gson;
import com.jieli.bmp_convert.BmpConvert;
import com.jieli.bmp_convert.OnConvertListener;
import com.jieli.jl_fatfs.interfaces.OnFatFileProgressListener;
import com.jieli.jl_fatfs.model.FatFile;
import com.jieli.jl_rcsp.interfaces.watch.OnWatchOpCallback;
import com.jieli.jl_rcsp.model.base.BaseError;
import com.jieli.jl_rcsp.model.response.ExternalFlashMsgResponse;
import com.jieli.jl_rcsp.task.SimpleTaskListener;
import com.jieli.jl_rcsp.task.contacts.DeviceContacts;
import com.jieli.jl_rcsp.task.contacts.ReadContactsTask;
import com.jieli.jl_rcsp.task.contacts.UpdateContactsTask;
import com.jieli.jl_rcsp.tool.DeviceStatusManager;
import com.yucheng.ycbtsdk.Constants;
import com.yucheng.ycbtsdk.bean.ContactsBean;
import com.yucheng.ycbtsdk.core.YCBTClientImpl;
import com.yucheng.ycbtsdk.core.YCSendBean;
import com.yucheng.ycbtsdk.gatt.BleHelper;
import com.yucheng.ycbtsdk.gatt.Reconnect;
import com.yucheng.ycbtsdk.jl.ALiIOTKit;
import com.yucheng.ycbtsdk.jl.WatchManager;
import com.yucheng.ycbtsdk.response.BleConnectResponse;
import com.yucheng.ycbtsdk.response.BleDataResponse;
import com.yucheng.ycbtsdk.response.BleDeviceToAppDataResponse;
import com.yucheng.ycbtsdk.response.BleRealDataResponse;
import com.yucheng.ycbtsdk.response.BleScanListResponse;
import com.yucheng.ycbtsdk.response.BleScanResponse;
import com.yucheng.ycbtsdk.upgrade.DfuCallBack;
import com.yucheng.ycbtsdk.upgrade.NordicDfuUpdateUtil;
import com.yucheng.ycbtsdk.utils.ByteUtil;
import com.yucheng.ycbtsdk.utils.DeviceSupportFunctionUtil;
import com.yucheng.ycbtsdk.utils.DialUtils;
import com.yucheng.ycbtsdk.utils.SPUtil;
import com.yucheng.ycbtsdk.utils.TimeUtil;
import com.yucheng.ycbtsdk.utils.UpgradeFirmwareUtil;
import com.yucheng.ycbtsdk.utils.YCBTLog;
import com.zhihu.matisse.internal.loader.AlbumLoader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;
import no.nordicsemi.android.dfu.DfuBaseService;

/* loaded from: classes4.dex */
public class YCBTClient {
    public static final int SecFrom30Year = 946684800;
    private static Context context;
    public static final int millisFromGMT = TimeZone.getDefault().getOffset(System.currentTimeMillis());
    public static boolean OpenLogSwitch = true;

    /* renamed from: com.yucheng.ycbtsdk.YCBTClient$1 */
    class AnonymousClass1 implements BleDataResponse {
        AnonymousClass1() {
        }

        @Override // com.yucheng.ycbtsdk.response.BleDataResponse
        public void onDataResponse(int i2, float f2, HashMap hashMap) {
        }
    }

    /* renamed from: com.yucheng.ycbtsdk.YCBTClient$10 */
    class AnonymousClass10 implements OnConvertListener {
        final /* synthetic */ BmpConvert val$bmpConvert;

        AnonymousClass10(BmpConvert bmpConvert) {
            r2 = bmpConvert;
        }

        @Override // com.jieli.bmp_convert.OnConvertListener
        public void onStart(String str) {
            YCBTLog.e("jl_watch_dial_start--path==" + str);
        }

        @Override // com.jieli.bmp_convert.OnConvertListener
        public void onStop(boolean z, String str) {
            if (BleDataResponse.this != null) {
                HashMap hashMap = new HashMap();
                hashMap.put(ClientCookie.PATH_ATTR, str);
                BleDataResponse.this.onDataResponse(z ? 0 : -1, 0.0f, hashMap);
            }
            BmpConvert bmpConvert = r2;
            if (bmpConvert != null) {
                bmpConvert.release();
            }
        }
    }

    /* renamed from: com.yucheng.ycbtsdk.YCBTClient$11 */
    class AnonymousClass11 implements OnFatFileProgressListener {
        AnonymousClass11() {
        }

        @Override // com.jieli.jl_fatfs.interfaces.OnFatFileProgressListener
        public void onProgress(float f2) {
            if (BleDataResponse.this != null) {
                HashMap hashMap = new HashMap();
                hashMap.put("progress", Float.valueOf(f2));
                hashMap.put("dataType", Integer.valueOf(Constants.DATATYPE.WatchDialProgress));
                BleDataResponse.this.onDataResponse(0, 0.0f, hashMap);
            }
        }

        @Override // com.jieli.jl_fatfs.interfaces.OnFatFileProgressListener
        public void onStart(String str) {
            if (BleDataResponse.this != null) {
                HashMap hashMap = new HashMap();
                hashMap.put("progress", Float.valueOf(0.0f));
                hashMap.put("dataType", Integer.valueOf(Constants.DATATYPE.WatchDialProgress));
                BleDataResponse.this.onDataResponse(0, 0.0f, hashMap);
            }
        }

        @Override // com.jieli.jl_fatfs.interfaces.OnFatFileProgressListener
        public void onStop(int i2) {
            BleDataResponse bleDataResponse;
            int i3;
            YCBTLog.e("jlInstallCustomizeDial result=" + i2);
            if (i2 == 0) {
                bleDataResponse = BleDataResponse.this;
                if (bleDataResponse == null) {
                    return;
                } else {
                    i3 = 0;
                }
            } else {
                bleDataResponse = BleDataResponse.this;
                if (bleDataResponse == null) {
                    return;
                } else {
                    i3 = -1;
                }
            }
            bleDataResponse.onDataResponse(i3, 0.0f, null);
        }
    }

    /* renamed from: com.yucheng.ycbtsdk.YCBTClient$12 */
    class AnonymousClass12 implements BleConnectResponse {
        final /* synthetic */ DfuCallBack val$callBack;
        final /* synthetic */ Context val$context;
        final /* synthetic */ String val$filePath;

        AnonymousClass12(Context context, String str, DfuCallBack dfuCallBack) {
            r1 = context;
            r2 = str;
            r3 = dfuCallBack;
        }

        @Override // com.yucheng.ycbtsdk.response.BleConnectResponse
        public void onConnectResponse(int i2) {
            if (i2 == 0) {
                if (YCBTClient.isOta() || YCBTClient.isForceOta()) {
                    UpgradeFirmwareUtil.startUpgrade(r1, r2, r3);
                }
            }
        }
    }

    /* renamed from: com.yucheng.ycbtsdk.YCBTClient$13 */
    class AnonymousClass13 implements BleDataResponse {
        final /* synthetic */ Context val$context;

        AnonymousClass13(Context context) {
            r2 = context;
        }

        @Override // com.yucheng.ycbtsdk.response.BleDataResponse
        public void onDataResponse(int i2, float f2, HashMap hashMap) {
            if (hashMap == null || ((Integer) hashMap.get(ServerProtocol.DIALOG_PARAM_STATE)).intValue() != 1) {
                ALiIOTKit.getInstance(r2).startChecked(BleDataResponse.this);
                return;
            }
            BleDataResponse bleDataResponse = BleDataResponse.this;
            if (bleDataResponse != null) {
                bleDataResponse.onDataResponse(0, 10.0f, null);
            }
        }
    }

    /* renamed from: com.yucheng.ycbtsdk.YCBTClient$14 */
    class AnonymousClass14 implements BleDataResponse {
        final /* synthetic */ BleDataResponse val$bleDataResponse;
        final /* synthetic */ Context val$context;

        AnonymousClass14(Context context, BleDataResponse bleDataResponse) {
            r1 = context;
            r2 = bleDataResponse;
        }

        @Override // com.yucheng.ycbtsdk.response.BleDataResponse
        public void onDataResponse(int i2, float f2, HashMap hashMap) {
            if (i2 == 0) {
                YCBTClient.aLiIOTKitStartChecked(r1, r2);
            } else {
                r2.onDataResponse(i2, f2, hashMap);
            }
        }
    }

    /* renamed from: com.yucheng.ycbtsdk.YCBTClient$2 */
    class AnonymousClass2 implements BleDataResponse {
        AnonymousClass2() {
        }

        @Override // com.yucheng.ycbtsdk.response.BleDataResponse
        public void onDataResponse(int i2, float f2, HashMap hashMap) {
        }
    }

    /* renamed from: com.yucheng.ycbtsdk.YCBTClient$3 */
    class AnonymousClass3 implements BleDataResponse {
        final /* synthetic */ String val$content;
        final /* synthetic */ BleDataResponse val$dataResponse;
        final /* synthetic */ String val$title;
        final /* synthetic */ int val$type;

        AnonymousClass3(String str, String str2, int i2, BleDataResponse bleDataResponse) {
            r1 = str;
            r2 = str2;
            r3 = i2;
            r4 = bleDataResponse;
        }

        @Override // com.yucheng.ycbtsdk.response.BleDataResponse
        public void onDataResponse(int i2, float f2, HashMap hashMap) {
            if (hashMap != null) {
                YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.AppMessageControl, ByteUtil.stringToByte(r1, r2, ((Integer) hashMap.get(AlbumLoader.COLUMN_COUNT)).intValue(), r3), 2, r4);
            }
        }
    }

    /* renamed from: com.yucheng.ycbtsdk.YCBTClient$4 */
    class AnonymousClass4 extends SimpleTaskListener {
        AnonymousClass4() {
        }

        @Override // com.jieli.jl_rcsp.task.SimpleTaskListener, com.jieli.jl_rcsp.task.TaskListener
        public void onBegin() {
        }

        @Override // com.jieli.jl_rcsp.task.SimpleTaskListener, com.jieli.jl_rcsp.task.TaskListener
        public void onError(int i2, String str) {
            if (BleDataResponse.this != null) {
                HashMap hashMap = new HashMap();
                hashMap.put("msg", str);
                BleDataResponse.this.onDataResponse(-1, 0.0f, hashMap);
            }
        }

        @Override // com.jieli.jl_rcsp.task.SimpleTaskListener, com.jieli.jl_rcsp.task.TaskListener
        public void onFinish() {
            BleDataResponse bleDataResponse = BleDataResponse.this;
            if (bleDataResponse != null) {
                bleDataResponse.onDataResponse(0, 0.0f, null);
            }
        }
    }

    /* renamed from: com.yucheng.ycbtsdk.YCBTClient$5 */
    class AnonymousClass5 extends SimpleTaskListener {
        final /* synthetic */ ReadContactsTask val$task;

        AnonymousClass5(ReadContactsTask readContactsTask) {
            r2 = readContactsTask;
        }

        @Override // com.jieli.jl_rcsp.task.SimpleTaskListener, com.jieli.jl_rcsp.task.TaskListener
        public void onBegin() {
        }

        @Override // com.jieli.jl_rcsp.task.SimpleTaskListener, com.jieli.jl_rcsp.task.TaskListener
        public void onError(int i2, String str) {
            if (BleDataResponse.this != null) {
                HashMap hashMap = new HashMap();
                hashMap.put("msg", str);
                BleDataResponse.this.onDataResponse(-1, 0.0f, hashMap);
            }
        }

        @Override // com.jieli.jl_rcsp.task.SimpleTaskListener, com.jieli.jl_rcsp.task.TaskListener
        public void onFinish() {
            if (BleDataResponse.this != null) {
                List<DeviceContacts> contacts = r2.getContacts();
                ArrayList arrayList = new ArrayList();
                for (DeviceContacts deviceContacts : contacts) {
                    arrayList.add(new ContactsBean(deviceContacts.getFileId(), deviceContacts.getName(), deviceContacts.getMobile()));
                }
                HashMap hashMap = new HashMap();
                hashMap.put("data", arrayList);
                BleDataResponse.this.onDataResponse(0, 0.0f, hashMap);
            }
        }
    }

    /* renamed from: com.yucheng.ycbtsdk.YCBTClient$6 */
    class AnonymousClass6 implements OnFatFileProgressListener {
        AnonymousClass6() {
        }

        @Override // com.jieli.jl_fatfs.interfaces.OnFatFileProgressListener
        public void onProgress(float f2) {
            if (BleDataResponse.this != null) {
                HashMap hashMap = new HashMap();
                hashMap.put("progress", Float.valueOf(f2));
                hashMap.put("dataType", Integer.valueOf(Constants.DATATYPE.WatchDialProgress));
                BleDataResponse.this.onDataResponse(0, 0.0f, hashMap);
            }
        }

        @Override // com.jieli.jl_fatfs.interfaces.OnFatFileProgressListener
        public void onStart(String str) {
            if (BleDataResponse.this != null) {
                HashMap hashMap = new HashMap();
                hashMap.put("progress", Float.valueOf(0.0f));
                hashMap.put("dataType", Integer.valueOf(Constants.DATATYPE.WatchDialProgress));
                BleDataResponse.this.onDataResponse(0, 0.0f, hashMap);
            }
        }

        @Override // com.jieli.jl_fatfs.interfaces.OnFatFileProgressListener
        public void onStop(int i2) {
            BleDataResponse bleDataResponse = BleDataResponse.this;
            if (bleDataResponse != null) {
                if (i2 == 0) {
                    i2 = 0;
                }
                bleDataResponse.onDataResponse(i2, 0.0f, null);
            }
        }
    }

    /* renamed from: com.yucheng.ycbtsdk.YCBTClient$7 */
    class AnonymousClass7 implements BleDataResponse {
        final /* synthetic */ int val$crc;
        final /* synthetic */ BleDataResponse val$dataResponse;
        final /* synthetic */ int val$lenth;

        /* renamed from: com.yucheng.ycbtsdk.YCBTClient$7$1 */
        class AnonymousClass1 implements BleDataResponse {
            final /* synthetic */ int val$finalUiFileOffset;

            AnonymousClass1(int i2) {
                r2 = i2;
            }

            /* JADX WARN: Code restructure failed: missing block: B:12:0x0027, code lost:
            
                if (r8 == 0) goto L46;
             */
            /* JADX WARN: Code restructure failed: missing block: B:6:0x001c, code lost:
            
                if (r8 == 0) goto L46;
             */
            /* JADX WARN: Code restructure failed: missing block: B:7:0x002a, code lost:
            
                r7 = r7 + 1;
             */
            @Override // com.yucheng.ycbtsdk.response.BleDataResponse
            /*
                Code decompiled incorrectly, please refer to instructions dump.
                To view partially-correct code enable 'Show inconsistent code' option in preferences
            */
            public void onDataResponse(int r7, float r8, java.util.HashMap r9) {
                /*
                    r6 = this;
                    if (r7 != 0) goto L11
                    if (r9 == 0) goto L11
                    java.lang.String r7 = "chipScheme"
                    java.lang.Object r7 = r9.get(r7)
                    java.lang.Integer r7 = (java.lang.Integer) r7
                    int r7 = r7.intValue()
                    goto L12
                L11:
                    r7 = 0
                L12:
                    if (r7 != 0) goto L1f
                    com.yucheng.ycbtsdk.YCBTClient$7 r7 = com.yucheng.ycbtsdk.YCBTClient.AnonymousClass7.this
                    int r7 = r1
                    int r8 = r7 % 1024
                    int r7 = r7 / 1024
                    if (r8 != 0) goto L2a
                    goto L2c
                L1f:
                    com.yucheng.ycbtsdk.YCBTClient$7 r7 = com.yucheng.ycbtsdk.YCBTClient.AnonymousClass7.this
                    int r7 = r1
                    int r8 = r7 % 4096
                    int r7 = r7 / 4096
                    if (r8 != 0) goto L2a
                    goto L2c
                L2a:
                    int r7 = r7 + 1
                L2c:
                    r2 = r7
                    com.yucheng.ycbtsdk.YCBTClient$7 r7 = com.yucheng.ycbtsdk.YCBTClient.AnonymousClass7.this
                    int r0 = r1
                    int r3 = r2
                    int r1 = r0 - r3
                    int r4 = r2
                    com.yucheng.ycbtsdk.response.BleDataResponse r5 = r3
                    com.yucheng.ycbtsdk.YCBTClient.otaUIFileInfo(r0, r1, r2, r3, r4, r5)
                    return
                */
                throw new UnsupportedOperationException("Method not decompiled: com.yucheng.ycbtsdk.YCBTClient.AnonymousClass7.AnonymousClass1.onDataResponse(int, float, java.util.HashMap):void");
            }
        }

        AnonymousClass7(int i2, int i3, BleDataResponse bleDataResponse) {
            r1 = i2;
            r2 = i3;
            r3 = bleDataResponse;
        }

        @Override // com.yucheng.ycbtsdk.response.BleDataResponse
        public void onDataResponse(int i2, float f2, HashMap hashMap) {
            if (i2 != 0 || hashMap == null) {
                r3.onDataResponse(1, 1.0f, null);
                return;
            }
            int intValue = ((Integer) hashMap.get("uiFileTotalLen")).intValue();
            int intValue2 = ((Integer) hashMap.get("uiFileOffset")).intValue();
            int intValue3 = ((Integer) hashMap.get("uiFileCheckSum")).intValue();
            if (intValue == 0 || intValue != r1 || intValue3 != r2) {
                intValue2 = 0;
            }
            YCBTClient.getChipScheme(new BleDataResponse() { // from class: com.yucheng.ycbtsdk.YCBTClient.7.1
                final /* synthetic */ int val$finalUiFileOffset;

                AnonymousClass1(int intValue22) {
                    r2 = intValue22;
                }

                @Override // com.yucheng.ycbtsdk.response.BleDataResponse
                public void onDataResponse(int i3, float f3, HashMap hashMap2) {
                    /*
                        this = this;
                        if (r7 != 0) goto L11
                        if (r9 == 0) goto L11
                        java.lang.String r7 = "chipScheme"
                        java.lang.Object r7 = r9.get(r7)
                        java.lang.Integer r7 = (java.lang.Integer) r7
                        int r7 = r7.intValue()
                        goto L12
                    L11:
                        r7 = 0
                    L12:
                        if (r7 != 0) goto L1f
                        com.yucheng.ycbtsdk.YCBTClient$7 r7 = com.yucheng.ycbtsdk.YCBTClient.AnonymousClass7.this
                        int r7 = r1
                        int r8 = r7 % 1024
                        int r7 = r7 / 1024
                        if (r8 != 0) goto L2a
                        goto L2c
                    L1f:
                        com.yucheng.ycbtsdk.YCBTClient$7 r7 = com.yucheng.ycbtsdk.YCBTClient.AnonymousClass7.this
                        int r7 = r1
                        int r8 = r7 % 4096
                        int r7 = r7 / 4096
                        if (r8 != 0) goto L2a
                        goto L2c
                    L2a:
                        int r7 = r7 + 1
                    L2c:
                        r2 = r7
                        com.yucheng.ycbtsdk.YCBTClient$7 r7 = com.yucheng.ycbtsdk.YCBTClient.AnonymousClass7.this
                        int r0 = r1
                        int r3 = r2
                        int r1 = r0 - r3
                        int r4 = r2
                        com.yucheng.ycbtsdk.response.BleDataResponse r5 = r3
                        com.yucheng.ycbtsdk.YCBTClient.otaUIFileInfo(r0, r1, r2, r3, r4, r5)
                        return
                    */
                    throw new UnsupportedOperationException("Method not decompiled: com.yucheng.ycbtsdk.YCBTClient.AnonymousClass7.AnonymousClass1.onDataResponse(int, float, java.util.HashMap):void");
                }
            });
        }
    }

    /* renamed from: com.yucheng.ycbtsdk.YCBTClient$8 */
    class AnonymousClass8 implements OnFatFileProgressListener {
        AnonymousClass8() {
        }

        @Override // com.jieli.jl_fatfs.interfaces.OnFatFileProgressListener
        public void onProgress(float f2) {
        }

        @Override // com.jieli.jl_fatfs.interfaces.OnFatFileProgressListener
        public void onStart(String str) {
        }

        @Override // com.jieli.jl_fatfs.interfaces.OnFatFileProgressListener
        public void onStop(int i2) {
            YCBTLog.e("jlWatchDialDelete result=" + i2);
            BleDataResponse bleDataResponse = BleDataResponse.this;
            if (bleDataResponse != null) {
                bleDataResponse.onDataResponse(i2, 0.0f, null);
            }
        }
    }

    /* renamed from: com.yucheng.ycbtsdk.YCBTClient$9 */
    class AnonymousClass9 implements OnWatchOpCallback<FatFile> {
        AnonymousClass9() {
        }

        @Override // com.jieli.jl_rcsp.interfaces.watch.OnWatchOpCallback
        public void onFailed(BaseError baseError) {
            YCBTLog.e("jlWatchDialSetCurrent error.getMessage()" + baseError.getMessage() + "  error.getCode()" + baseError.getCode());
            BleDataResponse.this.onDataResponse(-1, 0.0f, null);
        }

        @Override // com.jieli.jl_rcsp.interfaces.watch.OnWatchOpCallback
        public void onSuccess(FatFile fatFile) {
            YCBTLog.e("jlWatchDialSetCurrent result" + new Gson().toJson(fatFile));
            if (BleDataResponse.this != null) {
                HashMap hashMap = new HashMap();
                if (fatFile != null) {
                    hashMap.put("data", fatFile.toString());
                    BleDataResponse.this.onDataResponse(0, 0.0f, hashMap);
                }
            }
        }
    }

    public static void aLiIOTKitStartChecked(Context context2, BleDataResponse bleDataResponse) {
        if (getAuthPass()) {
            getALiIOTActivationState(new BleDataResponse() { // from class: com.yucheng.ycbtsdk.YCBTClient.13
                final /* synthetic */ Context val$context;

                AnonymousClass13(Context context22) {
                    r2 = context22;
                }

                @Override // com.yucheng.ycbtsdk.response.BleDataResponse
                public void onDataResponse(int i2, float f2, HashMap hashMap) {
                    if (hashMap == null || ((Integer) hashMap.get(ServerProtocol.DIALOG_PARAM_STATE)).intValue() != 1) {
                        ALiIOTKit.getInstance(r2).startChecked(BleDataResponse.this);
                        return;
                    }
                    BleDataResponse bleDataResponse2 = BleDataResponse.this;
                    if (bleDataResponse2 != null) {
                        bleDataResponse2.onDataResponse(0, 10.0f, null);
                    }
                }
            });
        } else {
            setAuthPass(new BleDataResponse() { // from class: com.yucheng.ycbtsdk.YCBTClient.14
                final /* synthetic */ BleDataResponse val$bleDataResponse;
                final /* synthetic */ Context val$context;

                AnonymousClass14(Context context22, BleDataResponse bleDataResponse2) {
                    r1 = context22;
                    r2 = bleDataResponse2;
                }

                @Override // com.yucheng.ycbtsdk.response.BleDataResponse
                public void onDataResponse(int i2, float f2, HashMap hashMap) {
                    if (i2 == 0) {
                        YCBTClient.aLiIOTKitStartChecked(r1, r2);
                    } else {
                        r2.onDataResponse(i2, f2, hashMap);
                    }
                }
            });
        }
    }

    public static void appAmbientLightMeasurementControl(int i2, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.AppAmbientLightMeasurementControl, new byte[]{(byte) i2}, 2, bleDataResponse);
    }

    public static void appAmbientTempHumidityMeasurementControl(int i2, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(800, new byte[]{(byte) i2}, 2, bleDataResponse);
    }

    public static void appBloodCalibration(int i2, int i3, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.AppBloodCalibration, new byte[]{(byte) i2, (byte) i3}, 2, bleDataResponse);
    }

    public static void appBloodSugarCalibration(int i2, int i3, int i4, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.AppBloodSugarCalibration, new byte[]{(byte) i2, (byte) i3, (byte) i4}, 2, bleDataResponse);
    }

    public static void appControlTakePhoto(int i2, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.AppControlTakePhoto, new byte[]{(byte) (i2 & 255)}, 2, bleDataResponse);
    }

    public static void appControlWave(int i2, int i3, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendDataType2Device(Constants.DATATYPE.AppControlWave, 14, new byte[]{(byte) i2, (byte) i3}, 2, bleDataResponse);
    }

    /* JADX WARN: Removed duplicated region for block: B:11:0x0020  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public static void appEarlyWarning(int r4, java.lang.String r5, com.yucheng.ycbtsdk.response.BleDataResponse r6) {
        /*
            r0 = 1
            if (r4 != r0) goto L6
            if (r5 != 0) goto L6
            return
        L6:
            r1 = 0
            r2 = 0
            if (r5 == 0) goto L16
            java.lang.String r3 = "UTF-8"
            byte[] r2 = r5.getBytes(r3)     // Catch: java.lang.Exception -> L12
            int r5 = r2.length     // Catch: java.lang.Exception -> L12
            goto L17
        L12:
            r5 = move-exception
            r5.printStackTrace()
        L16:
            r5 = r1
        L17:
            int r3 = r5 + 1
            byte[] r3 = new byte[r3]
            byte r4 = (byte) r4
            r3[r1] = r4
            if (r2 == 0) goto L23
            java.lang.System.arraycopy(r2, r1, r3, r0, r5)
        L23:
            com.yucheng.ycbtsdk.core.YCBTClientImpl r4 = com.yucheng.ycbtsdk.core.YCBTClientImpl.getInstance()
            r5 = 806(0x326, float:1.13E-42)
            r0 = 2
            r4.sendSingleData2Device(r5, r3, r0, r6)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.yucheng.ycbtsdk.YCBTClient.appEarlyWarning(int, java.lang.String, com.yucheng.ycbtsdk.response.BleDataResponse):void");
    }

    public static void appEcgTestEnd(BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendDataType2Device(Constants.DATATYPE.AppBloodSwitch, 11, new byte[]{0}, 3, bleDataResponse);
    }

    public static void appEcgTestStart(BleDataResponse bleDataResponse, BleRealDataResponse bleRealDataResponse) {
        AITools.getInstance().init();
        YCBTClientImpl.getInstance().sendDataType2Device(Constants.DATATYPE.AppBloodSwitch, 10, new byte[]{2}, 2, bleDataResponse);
        YCBTClientImpl.getInstance().registerEcgRealDataCallBack(bleRealDataResponse);
    }

    public static void appEffectiveHeart(int i2, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.AppEffectiveHeart, new byte[]{(byte) i2}, 2, bleDataResponse);
    }

    public static void appEffectiveStep(int i2, int i3, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.AppEffectiveStep, new byte[]{(byte) (i2 & 255), (byte) ((i2 >> 8) & 255), (byte) ((i2 >> 16) & 255), (byte) ((i2 >> 24) & 255), (byte) i3}, 2, bleDataResponse);
    }

    public static void appEmoticonIndex(int i2, int i3, int i4, String str, BleDataResponse bleDataResponse) {
        byte[] bArr;
        int i5;
        if (str == null || "".equals(str)) {
            bArr = null;
            i5 = 0;
        } else {
            if (str.length() >= 8) {
                str = getData(str, 8) + "…";
            }
            bArr = str.getBytes();
            i5 = bArr.length;
        }
        byte[] bArr2 = new byte[i5 + 3];
        bArr2[0] = (byte) i2;
        bArr2[1] = (byte) i3;
        bArr2[2] = (byte) i4;
        if (i5 != 0) {
            System.arraycopy(bArr, 0, bArr2, 3, i5);
        }
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.AppEmoticonIndex, bArr2, 2, bleDataResponse);
    }

    public static void appEmotionalMeasurementEnd(BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.AppStartMeasurement, new byte[]{0, 12}, 2, bleDataResponse);
        appControlWave(0, 0, bleDataResponse);
    }

    public static void appEmotionalMeasurementStart(BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.AppStartMeasurement, new byte[]{1, 12}, 2, bleDataResponse);
        appControlWave(1, 0, bleDataResponse);
    }

    public static void appFindDevice(int i2, int i3, int i4, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(768, new byte[]{(byte) i2, (byte) i3, (byte) i4}, 2, bleDataResponse);
    }

    public static void appHealthArg(int i2, int i3, int i4, int i5, BleDataResponse bleDataResponse) {
        byte[] bArr = new byte[14];
        bArr[0] = (byte) i2;
        bArr[1] = (byte) i3;
        bArr[2] = (byte) i4;
        bArr[3] = (byte) i5;
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.AppHealthArg, bArr, 2, bleDataResponse);
    }

    public static void appHealthWriteBack(int i2, String str, BleDataResponse bleDataResponse) {
        byte[] bytes;
        if (str != null) {
            try {
                bytes = str.getBytes("UTF-8");
            } catch (Exception e2) {
                e2.printStackTrace();
                return;
            }
        } else {
            bytes = null;
        }
        int length = bytes == null ? 0 : bytes.length;
        byte[] bArr = new byte[length + 1];
        bArr[0] = (byte) i2;
        if (bytes != null) {
            System.arraycopy(bytes, 0, bArr, 1, length);
        }
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.AppHealthWriteBack, bArr, 2, bleDataResponse);
    }

    /* JADX WARN: Removed duplicated region for block: B:17:0x001d A[Catch: Exception -> 0x0014, TryCatch #0 {Exception -> 0x0014, blocks: (B:19:0x0002, B:21:0x0008, B:6:0x001f, B:8:0x0051, B:9:0x0055, B:17:0x001d), top: B:18:0x0002 }] */
    /* JADX WARN: Removed duplicated region for block: B:5:0x001b  */
    /* JADX WARN: Removed duplicated region for block: B:8:0x0051 A[Catch: Exception -> 0x0014, TryCatch #0 {Exception -> 0x0014, blocks: (B:19:0x0002, B:21:0x0008, B:6:0x001f, B:8:0x0051, B:9:0x0055, B:17:0x001d), top: B:18:0x0002 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public static void appInsuranceNews(int r3, int r4, int r5, int r6, int r7, java.lang.String r8, com.yucheng.ycbtsdk.response.BleDataResponse r9) {
        /*
            if (r8 == 0) goto L16
            int r0 = r8.length()     // Catch: java.lang.Exception -> L14
            if (r0 <= 0) goto L16
            java.lang.String r0 = "UTF-8"
            byte[] r8 = r8.getBytes(r0)     // Catch: java.lang.Exception -> L14
            int r0 = r8.length     // Catch: java.lang.Exception -> L14
            r1 = 18
            if (r0 <= r1) goto L17
            return
        L14:
            r3 = move-exception
            goto L5f
        L16:
            r8 = 0
        L17:
            r0 = 8
            if (r8 != 0) goto L1d
            r1 = r0
            goto L1f
        L1d:
            int r1 = r8.length     // Catch: java.lang.Exception -> L14
            int r1 = r1 + r0
        L1f:
            byte[] r1 = new byte[r1]     // Catch: java.lang.Exception -> L14
            byte r3 = (byte) r3     // Catch: java.lang.Exception -> L14
            r2 = 0
            r1[r2] = r3     // Catch: java.lang.Exception -> L14
            byte r3 = (byte) r4     // Catch: java.lang.Exception -> L14
            r4 = 1
            r1[r4] = r3     // Catch: java.lang.Exception -> L14
            byte r3 = (byte) r5     // Catch: java.lang.Exception -> L14
            r4 = 2
            r1[r4] = r3     // Catch: java.lang.Exception -> L14
            byte r3 = (byte) r6     // Catch: java.lang.Exception -> L14
            r5 = 3
            r1[r5] = r3     // Catch: java.lang.Exception -> L14
            r3 = r7 & 255(0xff, float:3.57E-43)
            byte r3 = (byte) r3     // Catch: java.lang.Exception -> L14
            r5 = 4
            r1[r5] = r3     // Catch: java.lang.Exception -> L14
            int r3 = r7 >> 8
            r3 = r3 & 255(0xff, float:3.57E-43)
            byte r3 = (byte) r3     // Catch: java.lang.Exception -> L14
            r5 = 5
            r1[r5] = r3     // Catch: java.lang.Exception -> L14
            int r3 = r7 >> 16
            r3 = r3 & 255(0xff, float:3.57E-43)
            byte r3 = (byte) r3     // Catch: java.lang.Exception -> L14
            r5 = 6
            r1[r5] = r3     // Catch: java.lang.Exception -> L14
            int r3 = r7 >> 24
            r3 = r3 & 255(0xff, float:3.57E-43)
            byte r3 = (byte) r3     // Catch: java.lang.Exception -> L14
            r5 = 7
            r1[r5] = r3     // Catch: java.lang.Exception -> L14
            if (r8 == 0) goto L55
            int r3 = r8.length     // Catch: java.lang.Exception -> L14
            java.lang.System.arraycopy(r8, r2, r1, r0, r3)     // Catch: java.lang.Exception -> L14
        L55:
            com.yucheng.ycbtsdk.core.YCBTClientImpl r3 = com.yucheng.ycbtsdk.core.YCBTClientImpl.getInstance()     // Catch: java.lang.Exception -> L14
            r5 = 801(0x321, float:1.122E-42)
            r3.sendSingleData2Device(r5, r1, r4, r9)     // Catch: java.lang.Exception -> L14
            goto L62
        L5f:
            r3.printStackTrace()
        L62:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.yucheng.ycbtsdk.YCBTClient.appInsuranceNews(int, int, int, int, int, java.lang.String, com.yucheng.ycbtsdk.response.BleDataResponse):void");
    }

    public static void appLipidCalibration(int i2, int i3, int i4, BleDataResponse bleDataResponse) {
        byte[] bArr = new byte[11];
        bArr[0] = (byte) i2;
        bArr[1] = (byte) i3;
        bArr[2] = (byte) i4;
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.AppLipidCalibration, bArr, 2, bleDataResponse);
    }

    public static void appMobileModel(String str, BleDataResponse bleDataResponse) {
        if (str == null || str.length() < 1) {
            return;
        }
        try {
            YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.AppMobileModel, str.getBytes("UTF-8"), 2, bleDataResponse);
        } catch (Exception e2) {
            e2.printStackTrace();
        }
    }

    public static void appNewPushContacts(Context context2, List<ContactsBean> list, BleDataResponse bleDataResponse) {
        if (list == null) {
            list = new ArrayList<>();
        }
        if (SPUtil.getChipScheme() != 3 && getChipScheme() != 4) {
            appPushContactsSwitch(2, null);
            for (ContactsBean contactsBean : list) {
                appPushContacts(contactsBean.number, contactsBean.name, null);
            }
            appPushContactsSwitch(0, bleDataResponse);
            return;
        }
        ArrayList arrayList = new ArrayList();
        for (ContactsBean contactsBean2 : list) {
            DeviceContacts deviceContacts = new DeviceContacts(contactsBean2.id, contactsBean2.name, contactsBean2.number);
            String str = contactsBean2.name;
            if (str != null) {
                contactsBean2.name = ByteUtil.getData(str, 20);
            }
            arrayList.add(deviceContacts);
        }
        UpdateContactsTask updateContactsTask = new UpdateContactsTask(WatchManager.getInstance(), context2, arrayList);
        updateContactsTask.setListener(new SimpleTaskListener() { // from class: com.yucheng.ycbtsdk.YCBTClient.4
            AnonymousClass4() {
            }

            @Override // com.jieli.jl_rcsp.task.SimpleTaskListener, com.jieli.jl_rcsp.task.TaskListener
            public void onBegin() {
            }

            @Override // com.jieli.jl_rcsp.task.SimpleTaskListener, com.jieli.jl_rcsp.task.TaskListener
            public void onError(int i2, String str2) {
                if (BleDataResponse.this != null) {
                    HashMap hashMap = new HashMap();
                    hashMap.put("msg", str2);
                    BleDataResponse.this.onDataResponse(-1, 0.0f, hashMap);
                }
            }

            @Override // com.jieli.jl_rcsp.task.SimpleTaskListener, com.jieli.jl_rcsp.task.TaskListener
            public void onFinish() {
                BleDataResponse bleDataResponse2 = BleDataResponse.this;
                if (bleDataResponse2 != null) {
                    bleDataResponse2.onDataResponse(0, 0.0f, null);
                }
            }
        });
        updateContactsTask.start();
    }

    public static void appPushCallState(int i2, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.AppPushCallState, new byte[]{(byte) i2}, 2, bleDataResponse);
    }

    public static void appPushContacts(String str, String str2, BleDataResponse bleDataResponse) {
        try {
            if (!TextUtils.isEmpty(str) && !TextUtils.isEmpty(str2)) {
                String data = ByteUtil.getData(str, 20);
                String data2 = ByteUtil.getData(str2, 26);
                byte[] bytes = data.getBytes("UTF-8");
                byte[] bytes2 = data2.getBytes("UTF-8");
                if (bytes.length <= 20 && bytes2.length <= 26) {
                    byte[] bArr = new byte[bytes.length + 3 + bytes2.length];
                    bArr[0] = 1;
                    bArr[1] = (byte) bytes.length;
                    bArr[2] = (byte) bytes2.length;
                    System.arraycopy(bytes, 0, bArr, 3, bytes.length);
                    System.arraycopy(bytes2, 0, bArr, bytes.length + 3, bytes2.length);
                    YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.AppPushContacts, bArr, 2, bleDataResponse);
                    return;
                }
                YCBTLog.e("phoneNumber or name's length is too long");
            }
        } catch (Exception e2) {
            e2.printStackTrace();
        }
    }

    public static void appPushContactsSwitch(int i2, BleDataResponse bleDataResponse) {
        try {
            byte[] bArr = new byte[49];
            bArr[0] = (byte) i2;
            YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.AppPushContacts, bArr, 2, bleDataResponse);
        } catch (Exception e2) {
            e2.printStackTrace();
        }
    }

    public static void appPushFemalePhysiological(long j2, int i2, int i3, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.AppPushFemalePhysiological, new byte[]{(byte) (j2 - 946684800), (byte) ((r5 >> 8) & 255), (byte) ((r5 >> 16) & 255), (byte) ((r5 >> 24) & 255), (byte) i2, (byte) i3, 0, 0, 0, 0, 0}, 2, bleDataResponse);
    }

    /* JADX WARN: Removed duplicated region for block: B:11:0x0020  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public static void appPushMessage(int r3, java.lang.String r4, com.yucheng.ycbtsdk.response.BleDataResponse r5) {
        /*
            r0 = 6
            if (r3 != r0) goto L6
            if (r4 != 0) goto L6
            return
        L6:
            r0 = 0
            r1 = 0
            if (r4 == 0) goto L16
            java.lang.String r2 = "UTF-8"
            byte[] r1 = r4.getBytes(r2)     // Catch: java.lang.Exception -> L12
            int r4 = r1.length     // Catch: java.lang.Exception -> L12
            goto L17
        L12:
            r4 = move-exception
            r4.printStackTrace()
        L16:
            r4 = r0
        L17:
            int r2 = r4 + 1
            byte[] r2 = new byte[r2]
            byte r3 = (byte) r3
            r2[r0] = r3
            if (r1 == 0) goto L24
            r3 = 1
            java.lang.System.arraycopy(r1, r0, r2, r3, r4)
        L24:
            com.yucheng.ycbtsdk.core.YCBTClientImpl r3 = com.yucheng.ycbtsdk.core.YCBTClientImpl.getInstance()
            r4 = 807(0x327, float:1.131E-42)
            r0 = 2
            r3.sendSingleData2Device(r4, r2, r0, r5)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.yucheng.ycbtsdk.YCBTClient.appPushMessage(int, java.lang.String, com.yucheng.ycbtsdk.response.BleDataResponse):void");
    }

    public static void appPushTempAndHumidCalibration(int i2, int i3, int i4, int i5, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.AppPushTempAndHumidCalibration, new byte[]{(byte) i2, (byte) i3, (byte) i4, (byte) i5}, 2, bleDataResponse);
    }

    public static void appRealAllDataFromDevice(int i2, int i3, BleDataResponse bleDataResponse) {
        if (i3 > 60 || i3 < 1) {
            return;
        }
        YCBTClientImpl.getInstance().sendSingleData2Device(268, new byte[]{1, (byte) i3}, 2, bleDataResponse);
        byte b2 = (byte) i2;
        byte b3 = (byte) (i3 * 60);
        YCBTClientImpl.getInstance().sendDataType2Device(Constants.DATATYPE.AppControlReal, 12, new byte[]{b2, 1, b3}, 2, bleDataResponse);
        YCBTClientImpl.getInstance().sendDataType2Device(Constants.DATATYPE.AppControlReal, 12, new byte[]{b2, 2, b3}, 2, bleDataResponse);
        YCBTClientImpl.getInstance().sendDataType2Device(Constants.DATATYPE.AppControlReal, 12, new byte[]{b2, 3, b3}, 2, bleDataResponse);
        YCBTClientImpl.getInstance().sendDataType2Device(Constants.DATATYPE.AppControlReal, 12, new byte[]{b2, 4, b3}, 2, bleDataResponse);
        YCBTClientImpl.getInstance().sendDataType2Device(Constants.DATATYPE.AppControlReal, 12, new byte[]{b2, 5, b3}, 2, bleDataResponse);
    }

    public static void appRealDataFromDevice(int i2, int i3, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendDataType2Device(Constants.DATATYPE.AppControlReal, 12, new byte[]{(byte) i2, (byte) i3, 2}, 2, bleDataResponse);
    }

    public static void appRealSportFromDevice(int i2, BleDataResponse bleDataResponse) {
        appRealDataFromDevice(i2, 0, bleDataResponse);
    }

    public static void appRegisterRealDataCallBack(BleRealDataResponse bleRealDataResponse) {
        YCBTClientImpl.getInstance().registerRealDataCallBack(bleRealDataResponse);
    }

    public static void appRunMode(int i2, int i3, BleDataResponse bleDataResponse) {
        int i4;
        int i5;
        byte[] bArr = {(byte) i2, (byte) i3};
        if (i2 == 1) {
            i5 = 8;
        } else {
            if (i2 != 0) {
                i4 = 1;
                YCBTClientImpl.getInstance().sendDataType2Device(Constants.DATATYPE.AppRunMode, i4, bArr, 2, bleDataResponse);
            }
            i5 = 9;
        }
        i4 = i5;
        YCBTClientImpl.getInstance().sendDataType2Device(Constants.DATATYPE.AppRunMode, i4, bArr, 2, bleDataResponse);
    }

    public static void appRunModeEnd(int i2, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendDataType2Device(Constants.DATATYPE.AppRunMode, 9, new byte[]{0, (byte) i2}, 2, bleDataResponse);
    }

    public static void appRunModeStart(int i2, BleDataResponse bleDataResponse, BleRealDataResponse bleRealDataResponse) {
        YCBTClientImpl.getInstance().sendDataType2Device(Constants.DATATYPE.AppRunMode, 8, new byte[]{1, (byte) i2}, 2, bleDataResponse);
        YCBTClientImpl.getInstance().registerRealDataCallBack(bleRealDataResponse);
    }

    public static void appSendCardNumber(int i2, String str, BleDataResponse bleDataResponse) {
        if (str == null || str.length() < 1) {
            if (bleDataResponse != null) {
                bleDataResponse.onDataResponse(-1, -1.0f, null);
                return;
            }
            return;
        }
        byte[] bytes = str.getBytes(StandardCharsets.UTF_8);
        int length = bytes.length + 2;
        byte[] bArr = new byte[length];
        bArr[0] = (byte) i2;
        System.arraycopy(bytes, 0, bArr, 1, bytes.length);
        bArr[length - 1] = 0;
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.AppSendCardNumber, bArr, 2, bleDataResponse);
    }

    public static void appSendLocationNumber(int i2, String str, BleDataResponse bleDataResponse) {
        if (str == null || str.length() < 1) {
            if (bleDataResponse != null) {
                bleDataResponse.onDataResponse(-1, -1.0f, null);
                return;
            }
            return;
        }
        byte[] bytes = str.getBytes(StandardCharsets.UTF_8);
        int length = bytes.length + 2;
        byte[] bArr = new byte[length];
        bArr[0] = (byte) i2;
        System.arraycopy(bytes, 0, bArr, 1, bytes.length);
        bArr[length - 1] = 0;
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.AppSendLocationNumber, bArr, 2, bleDataResponse);
    }

    public static void appSendMeasureNumber(int i2, long j2, int i3, int i4, int i5, int i6, int i7, int i8, BleDataResponse bleDataResponse) {
        long offset = (j2 - 946684800) + (TimeZone.getDefault().getOffset(System.currentTimeMillis()) / 1000);
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.AppSendMeasureNumber, new byte[]{(byte) i2, (byte) (offset & 255), (byte) ((offset >> 8) & 255), (byte) ((offset >> 16) & 255), (byte) ((offset >> 24) & 255), (byte) i3, (byte) i4, (byte) i5, (byte) i6, (byte) i7, (byte) i8}, 2, bleDataResponse);
    }

    public static void appSendMeasureNumber(int i2, long j2, int i3, int i4, BleDataResponse bleDataResponse) {
        appSendMeasureNumber(i2, j2, i3, i4, 0, 0, 0, 0, bleDataResponse);
    }

    public static void appSendPDNumber(String str, String str2, int i2, List<HashMap<String, Integer>> list, BleDataResponse bleDataResponse) {
        if (str != null && str.length() >= 1 && str2 != null && str2.length() >= 1 && list != null) {
            YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.AppPDNumber, ByteUtil.pdNumberToByte(str, 32, str2, 10, list, i2), 2, bleDataResponse);
        } else if (bleDataResponse != null) {
            bleDataResponse.onDataResponse(-1, -1.0f, null);
        }
    }

    public static void appSendProductInfo(int i2, String str, BleDataResponse bleDataResponse) {
        if (str == null) {
            if (bleDataResponse != null) {
                bleDataResponse.onDataResponse(-1, 0.0f, null);
                return;
            }
            return;
        }
        byte[] bArr = new byte[0];
        try {
            bArr = str.getBytes("UTF-8");
        } catch (UnsupportedEncodingException e2) {
            e2.printStackTrace();
        }
        byte[] bArr2 = new byte[bArr.length + 2];
        bArr2[0] = (byte) i2;
        System.arraycopy(bArr, 0, bArr2, 1, bArr.length);
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.AppSendProductInfo, bArr2, 2, bleDataResponse);
    }

    public static void appSendToken(String str, BleDataResponse bleDataResponse) {
        if (str == null || str.length() < 1) {
            if (bleDataResponse != null) {
                bleDataResponse.onDataResponse(-1, -1.0f, null);
            }
        } else {
            byte[] bytes = str.getBytes(StandardCharsets.UTF_8);
            int length = bytes.length + 1;
            byte[] bArr = new byte[length];
            System.arraycopy(bytes, 0, bArr, 0, bytes.length);
            bArr[length - 1] = 0;
            YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.AppSendToken, bArr, 2, bleDataResponse);
        }
    }

    public static void appSendTokenStatus(int i2, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.AppSendTokenStatus, new byte[]{(byte) (i2 & 255)}, 2, bleDataResponse);
    }

    public static void appSendUUID(String str, BleDataResponse bleDataResponse) {
        if (str == null || !(str.length() == 32 || str.length() == 36)) {
            if (bleDataResponse != null) {
                bleDataResponse.onDataResponse(-1, 0.0f, null);
                return;
            }
            return;
        }
        if (str.length() == 36) {
            str = str.replaceAll(HelpFormatter.DEFAULT_OPT_PREFIX, "");
        }
        byte[] bArr = new byte[16];
        for (int i2 = 0; i2 < 16; i2++) {
            try {
                bArr[i2] = (byte) Integer.parseInt(str.substring(i2, i2 + 2), 16);
            } catch (NumberFormatException e2) {
                e2.printStackTrace();
                if (bleDataResponse != null) {
                    bleDataResponse.onDataResponse(-1, 0.0f, null);
                    return;
                }
                return;
            }
        }
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.AppSendUUID, bArr, 2, bleDataResponse);
    }

    public static void appSengMessageToDevice(int i2, String str, String str2, BleDataResponse bleDataResponse) {
        if (str == null || str.length() < 1 || str2 == null || str2.length() < 1) {
            return;
        }
        getDeviceScreenInfo(new BleDataResponse() { // from class: com.yucheng.ycbtsdk.YCBTClient.3
            final /* synthetic */ String val$content;
            final /* synthetic */ BleDataResponse val$dataResponse;
            final /* synthetic */ String val$title;
            final /* synthetic */ int val$type;

            AnonymousClass3(String str3, String str22, int i22, BleDataResponse bleDataResponse2) {
                r1 = str3;
                r2 = str22;
                r3 = i22;
                r4 = bleDataResponse2;
            }

            @Override // com.yucheng.ycbtsdk.response.BleDataResponse
            public void onDataResponse(int i22, float f2, HashMap hashMap) {
                if (hashMap != null) {
                    YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.AppMessageControl, ByteUtil.stringToByte(r1, r2, ((Integer) hashMap.get(AlbumLoader.COLUMN_COUNT)).intValue(), r3), 2, r4);
                }
            }
        });
    }

    public static void appSensorSwitchControl(int i2, int i3, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.AppSensorSwitchControl, new byte[]{(byte) i2, (byte) i3}, 2, bleDataResponse);
    }

    public static void appShutDown(int i2, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.AppShutDown, new byte[]{(byte) i2}, 2, bleDataResponse);
    }

    public static void appSleepWriteBack(int i2, int i3, int i4, int i5, int i6, int i7, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.AppSleepWriteBack, new byte[]{(byte) i2, (byte) i3, (byte) i4, (byte) i5, (byte) i6, (byte) i7}, 2, bleDataResponse);
    }

    public static void appStartBloodMeasurement(int i2, int i3, int i4, int i5, int i6, int i7, int i8, int i9, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.AppStartBloodMeasurement, new byte[]{(byte) i2, (byte) i3, (byte) i4, (byte) i5, (byte) i6, (byte) i7, (byte) i8, (byte) i9}, 2, bleDataResponse);
    }

    public static void appStartMeasurement(int i2, int i3, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.AppStartMeasurement, new byte[]{(byte) i2, (byte) i3}, 2, bleDataResponse);
    }

    public static void appTemperatureCode(int i2, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.AppTemperatureCode, new byte[]{(byte) i2}, 2, bleDataResponse);
    }

    public static void appTemperatureCorrect(int i2, int i3, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.AppTemperatureCorrect, new byte[]{(byte) i2, (byte) i3}, 2, bleDataResponse);
    }

    public static void appTemperatureMeasure(int i2, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.AppTemperatureMeasure, new byte[]{(byte) i2}, 2, bleDataResponse);
    }

    public static void appTodayWeather(String str, String str2, String str3, int i2, BleDataResponse bleDataResponse) {
        try {
            byte[] bytes = str.getBytes("UTF-8");
            byte[] bytes2 = str2.getBytes("UTF-8");
            byte[] bytes3 = str3.getBytes("UTF-8");
            int length = bytes.length;
            int length2 = bytes2.length;
            int length3 = bytes3.length;
            byte[] bArr = new byte[length + 3 + 3 + length2 + 3 + length3 + 3 + 2];
            bArr[0] = 2;
            bArr[1] = (byte) (length3 & 255);
            bArr[2] = (byte) ((length3 >> 8) & 255);
            System.arraycopy(bytes3, 0, bArr, 3, length3);
            int i3 = length3 + 3;
            int i4 = i3 + 1;
            bArr[i3] = 0;
            int i5 = i4 + 1;
            bArr[i4] = (byte) (length & 255);
            int i6 = i5 + 1;
            bArr[i5] = (byte) ((length >> 8) & 255);
            System.arraycopy(bytes, 0, bArr, i6, length);
            int i7 = i6 + length;
            int i8 = i7 + 1;
            bArr[i7] = 1;
            int i9 = i8 + 1;
            bArr[i8] = (byte) (length2 & 255);
            int i10 = i9 + 1;
            bArr[i9] = (byte) ((length2 >> 8) & 255);
            System.arraycopy(bytes2, 0, bArr, i10, length2);
            int i11 = i10 + length2;
            int i12 = i11 + 1;
            bArr[i11] = 4;
            int i13 = i12 + 1;
            bArr[i12] = 2;
            int i14 = i13 + 1;
            bArr[i13] = 0;
            bArr[i14] = (byte) (i2 & 255);
            bArr[i14 + 1] = (byte) ((i2 >> 8) & 255);
            YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.AppTodayWeather, bArr, 2, bleDataResponse);
        } catch (UnsupportedEncodingException e2) {
            e2.printStackTrace();
        }
    }

    public static void appTodayWeather(String str, String str2, String str3, int i2, String str4, String str5, String str6, int i3, BleDataResponse bleDataResponse) {
        byte[] bArr;
        int i4;
        byte[] bArr2;
        byte[] bArr3;
        int i5;
        byte[] bArr4;
        int i6;
        try {
            byte[] bytes = str.getBytes("UTF-8");
            byte[] bytes2 = str2.getBytes("UTF-8");
            byte[] bytes3 = str3.getBytes("UTF-8");
            byte[] bArr5 = {(byte) i3};
            int length = bytes.length;
            int length2 = bytes2.length;
            int length3 = bytes3.length;
            int i7 = length + 3 + 3 + length2 + 3 + length3 + 3 + 2;
            if (str4 != null) {
                bArr = str4.getBytes("UTF-8");
                i4 = bArr.length;
                i7 += i4 + 3;
            } else {
                bArr = null;
                i4 = 0;
            }
            if (str5 != null) {
                bArr3 = str5.getBytes("UTF-8");
                bArr2 = bArr5;
                i5 = bArr3.length;
                i7 += i5 + 3;
            } else {
                bArr2 = bArr5;
                bArr3 = null;
                i5 = 0;
            }
            if (str6 != null) {
                bArr4 = str6.getBytes("UTF-8");
                i6 = bArr4.length;
                i7 += i6 + 3;
            } else {
                bArr4 = null;
                i6 = 0;
            }
            byte[] bArr6 = new byte[i7 + 4];
            bArr6[0] = 2;
            int i8 = i6;
            bArr6[1] = (byte) (length3 & 255);
            bArr6[2] = (byte) ((length3 >> 8) & 255);
            byte[] bArr7 = bArr4;
            System.arraycopy(bytes3, 0, bArr6, 3, length3);
            int i9 = length3 + 3;
            int i10 = i9 + 1;
            bArr6[i9] = 0;
            int i11 = i10 + 1;
            bArr6[i10] = (byte) (length & 255);
            int i12 = i11 + 1;
            bArr6[i11] = (byte) ((length >> 8) & 255);
            System.arraycopy(bytes, 0, bArr6, i12, length);
            int i13 = i12 + length;
            int i14 = i13 + 1;
            bArr6[i13] = 1;
            int i15 = i14 + 1;
            bArr6[i14] = (byte) (length2 & 255);
            int i16 = i15 + 1;
            bArr6[i15] = (byte) ((length2 >> 8) & 255);
            System.arraycopy(bytes2, 0, bArr6, i16, length2);
            int i17 = i16 + length2;
            int i18 = i17 + 1;
            bArr6[i17] = 4;
            int i19 = i18 + 1;
            bArr6[i18] = 2;
            int i20 = i19 + 1;
            bArr6[i19] = 0;
            int i21 = i20 + 1;
            bArr6[i20] = (byte) (i2 & 255);
            int i22 = i21 + 1;
            bArr6[i21] = (byte) ((i2 >> 8) & 255);
            if (str4 != null) {
                int i23 = i22 + 1;
                bArr6[i22] = 6;
                int i24 = i23 + 1;
                bArr6[i23] = (byte) (i4 & 255);
                int i25 = i24 + 1;
                bArr6[i24] = (byte) ((i4 >> 8) & 255);
                System.arraycopy(bArr, 0, bArr6, i25, i4);
                i22 = i25 + i4;
            }
            if (str5 != null) {
                int i26 = i22 + 1;
                bArr6[i22] = 7;
                int i27 = i26 + 1;
                bArr6[i26] = (byte) (i5 & 255);
                int i28 = i27 + 1;
                bArr6[i27] = (byte) ((i5 >> 8) & 255);
                System.arraycopy(bArr3, 0, bArr6, i28, i5);
                i22 = i28 + i5;
            }
            if (bArr7 != null) {
                int i29 = i22 + 1;
                bArr6[i22] = 8;
                int i30 = i29 + 1;
                bArr6[i29] = (byte) (i8 & 255);
                int i31 = i30 + 1;
                bArr6[i30] = (byte) ((i8 >> 8) & 255);
                System.arraycopy(bArr7, 0, bArr6, i31, i8);
                i22 = i8 + i31;
            }
            int i32 = i22 + 1;
            bArr6[i22] = 9;
            int i33 = i32 + 1;
            bArr6[i32] = (byte) 1;
            bArr6[i33] = (byte) 0;
            System.arraycopy(bArr2, 0, bArr6, i33 + 1, 1);
            YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.AppTodayWeather, bArr6, 2, bleDataResponse);
        } catch (UnsupportedEncodingException e2) {
            e2.printStackTrace();
        }
    }

    public static void appTomorrowWeather(String str, String str2, String str3, int i2, BleDataResponse bleDataResponse) {
        try {
            byte[] bytes = str.getBytes("UTF-8");
            byte[] bytes2 = str2.getBytes("UTF-8");
            byte[] bytes3 = str3.getBytes("UTF-8");
            int length = bytes.length;
            int length2 = bytes2.length;
            int length3 = bytes3.length;
            byte[] bArr = new byte[length + 3 + 3 + length2 + 3 + length3 + 3 + 2];
            bArr[0] = 2;
            bArr[1] = (byte) (length3 & 255);
            bArr[2] = (byte) ((length3 >> 8) & 255);
            System.arraycopy(bytes3, 0, bArr, 3, length3);
            int i3 = length3 + 3;
            int i4 = i3 + 1;
            bArr[i3] = 0;
            int i5 = i4 + 1;
            bArr[i4] = (byte) (length & 255);
            int i6 = i5 + 1;
            bArr[i5] = (byte) ((length >> 8) & 255);
            System.arraycopy(bytes, 0, bArr, i6, length);
            int i7 = i6 + length;
            int i8 = i7 + 1;
            bArr[i7] = 1;
            int i9 = i8 + 1;
            bArr[i8] = (byte) (length2 & 255);
            int i10 = i9 + 1;
            bArr[i9] = (byte) ((length2 >> 8) & 255);
            System.arraycopy(bytes2, 0, bArr, i10, length2);
            int i11 = i10 + length2;
            int i12 = i11 + 1;
            bArr[i11] = 4;
            int i13 = i12 + 1;
            bArr[i12] = 2;
            int i14 = i13 + 1;
            bArr[i13] = 0;
            bArr[i14] = (byte) (i2 & 255);
            bArr[i14 + 1] = (byte) ((i2 >> 8) & 255);
            YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.AppTomorrowWeather, bArr, 2, bleDataResponse);
        } catch (UnsupportedEncodingException e2) {
            e2.printStackTrace();
        }
    }

    public static void appUpgradeReminder(int i2, int i3, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.AppUpgradeReminder, new byte[]{(byte) i2, (byte) i3}, 2, bleDataResponse);
    }

    public static void appUricAcidCalibration(int i2, int i3, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.AppUricAcidCalibration, new byte[]{(byte) i2, (byte) i3, (byte) ((i3 >> 8) & 255), 0, 0, 0, 0}, 2, bleDataResponse);
    }

    public static void appUserInfoWriteBack(int i2, String str, BleDataResponse bleDataResponse) {
        byte[] bytes;
        if (str != null) {
            try {
                bytes = str.getBytes("UTF-8");
            } catch (Exception e2) {
                e2.printStackTrace();
                return;
            }
        } else {
            bytes = null;
        }
        int length = bytes == null ? 0 : bytes.length;
        byte[] bArr = new byte[length + 3];
        bArr[0] = (byte) i2;
        bArr[1] = (byte) (length & 255);
        bArr[2] = (byte) ((length >> 8) & 255);
        if (bytes != null) {
            System.arraycopy(bytes, 0, bArr, 1, length);
        }
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.AppUserInfoWriteBack, bArr, 2, bleDataResponse);
    }

    public static void appWritebackData(int i2, int i3, int i4, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.AppWritebackData, new byte[]{(byte) i2, (byte) i3, (byte) i4, 0, 0, 0}, 2, bleDataResponse);
    }

    public static void checkALiIOTKit(Context context2, BleDataResponse bleDataResponse) {
        if (getAuthPass()) {
            ALiIOTKit.getInstance(context2).startChecked(bleDataResponse);
        } else {
            setAuthPass(null);
        }
    }

    public static void checkALiIOTKit(BleDataResponse bleDataResponse) {
        if (getAuthPass()) {
            ALiIOTKit.getInstance(context).startChecked(bleDataResponse);
        } else {
            setAuthPass(null);
        }
    }

    public static void collectDeleteEcgPpg(int i2, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.Collect_DeleteTimestamp, new byte[]{0, (byte) (i2 & 255), (byte) ((i2 >> 8) & 255), (byte) ((i2 >> 16) & 255), (byte) ((i2 >> 24) & 255)}, 2, bleDataResponse);
    }

    public static void collectEcgDataWithIndex(int i2, BleDataResponse bleDataResponse) {
        AITools.getInstance().init();
        YCBTClientImpl.getInstance().sendDataType2Device(Constants.DATATYPE.Collect_GetWithIndex, 5, new byte[]{0, (byte) (i2 & 255), (byte) ((i2 >> 8) & 255), 1}, 1, bleDataResponse);
    }

    public static void collectEcgDataWithTimestamp(long j2, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendDataType2Device(Constants.DATATYPE.Collect_GetWithTimestamp, 5, new byte[]{0, (byte) (j2 & 255), (byte) ((j2 >> 8) & 255), (byte) ((j2 >> 16) & 255), (byte) ((j2 >> 24) & 255), 1}, 1, bleDataResponse);
    }

    public static void collectEcgList(BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendDataType2Device(1792, 4, new byte[]{0}, 1, bleDataResponse);
    }

    public static void collectHistoryDataWithIndex(int i2, int i3, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendDataType2Device(Constants.DATATYPE.Collect_GetWithIndex, 5, new byte[]{(byte) i2, (byte) (i3 & 255), (byte) ((i3 >> 8) & 255), 1}, 1, bleDataResponse);
    }

    public static void collectHistoryDataWithTimestamp(int i2, long j2, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendDataType2Device(Constants.DATATYPE.Collect_GetWithTimestamp, 5, new byte[]{(byte) i2, (byte) (j2 & 255), (byte) ((j2 >> 8) & 255), (byte) ((j2 >> 16) & 255), (byte) ((j2 >> 24) & 255), 1}, 1, bleDataResponse);
    }

    public static void collectHistoryListData(int i2, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendDataType2Device(1792, 13, new byte[]{(byte) i2}, 1, bleDataResponse);
    }

    public static void collectPpgDataWithIndex(int i2, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendDataType2Device(Constants.DATATYPE.Collect_GetWithIndex, 7, new byte[]{1, (byte) (i2 & 255), (byte) ((i2 >> 8) & 255), 1}, 1, bleDataResponse);
    }

    public static void collectPpgDataWithTimestamp(long j2, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendDataType2Device(Constants.DATATYPE.Collect_GetWithTimestamp, 7, new byte[]{1, (byte) (j2 & 255), (byte) ((j2 >> 8) & 255), (byte) ((j2 >> 16) & 255), (byte) ((j2 >> 24) & 255), 1}, 1, bleDataResponse);
    }

    public static void collectPpgList(BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendDataType2Device(1792, 6, new byte[]{1}, 1, bleDataResponse);
    }

    public static void connectBle(String str, BleConnectResponse bleConnectResponse) {
        String bindedDeviceName = SPUtil.getBindedDeviceName();
        if (TextUtils.isEmpty(str)) {
            return;
        }
        if (!str.equals(SPUtil.getBindedDeviceMac())) {
            bindedDeviceName = "";
            SPUtil.saveBindedDeviceMac("");
            SPUtil.saveBindedDeviceName("");
        }
        connectBle(str, bindedDeviceName, bleConnectResponse);
    }

    public static void connectBle(String str, String str2, long j2, BleConnectResponse bleConnectResponse) {
        YCBTLog.e("YCBTClient connectBle mac=" + str);
        if (TextUtils.isEmpty(str)) {
            return;
        }
        if (!str.equals(SPUtil.getBindedDeviceMac())) {
            str2 = "";
            SPUtil.saveBindedDeviceMac("");
            SPUtil.saveBindedDeviceName("");
        }
        YCBTClientImpl.getInstance().connectBle(str, str2, j2, bleConnectResponse);
    }

    public static void connectBle(String str, String str2, BleConnectResponse bleConnectResponse) {
        connectBle(str, str2, 15000L, bleConnectResponse);
    }

    public static int connectState() {
        return YCBTClientImpl.getInstance().connectState();
    }

    public static void createBond() {
        BleHelper.getHelper().initBond();
    }

    /* JADX WARN: Code restructure failed: missing block: B:17:0x002d, code lost:
    
        if (r5 != 4) goto L79;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public static void dataSetting(int r4, int r5, int r6, int r7, com.yucheng.ycbtsdk.response.BleDataResponse r8) {
        /*
            r0 = 6
            byte[] r0 = new byte[r0]
            byte r1 = (byte) r4
            r2 = 0
            r0[r2] = r1
            byte r1 = (byte) r5
            r2 = 1
            r0[r2] = r1
            r1 = 3
            r3 = 2
            if (r4 == r2) goto L4d
            if (r4 == r3) goto L26
            if (r4 == r1) goto L14
            return
        L14:
            if (r5 == r2) goto L1b
            if (r5 == r3) goto L1b
            if (r5 == r1) goto L1b
            goto L66
        L1b:
            byte r4 = (byte) r6
            r0[r3] = r4
            int r4 = r6 >> 8
            r4 = r4 & 255(0xff, float:3.57E-43)
            byte r4 = (byte) r4
            r0[r1] = r4
            goto L66
        L26:
            r4 = 4
            if (r5 == r2) goto L3b
            if (r5 == r3) goto L30
            if (r5 == r1) goto L3b
            if (r5 == r4) goto L3b
            goto L66
        L30:
            byte r4 = (byte) r6
            r0[r3] = r4
            int r4 = r6 >> 8
            r4 = r4 & 255(0xff, float:3.57E-43)
            byte r4 = (byte) r4
            r0[r1] = r4
            goto L66
        L3b:
            byte r5 = (byte) r6
            r0[r3] = r5
            int r5 = r6 >> 8
            r5 = r5 & 255(0xff, float:3.57E-43)
            byte r5 = (byte) r5
            r0[r1] = r5
            int r5 = r6 >> 16
            r5 = r5 & 255(0xff, float:3.57E-43)
            byte r5 = (byte) r5
            r0[r4] = r5
            goto L66
        L4d:
            switch(r5) {
                case 0: goto L63;
                case 1: goto L5c;
                case 2: goto L63;
                case 3: goto L63;
                case 4: goto L5c;
                case 5: goto L63;
                case 6: goto L51;
                case 7: goto L5c;
                case 8: goto L63;
                case 9: goto L5c;
                case 10: goto L63;
                default: goto L50;
            }
        L50:
            return
        L51:
            byte r4 = (byte) r6
            r0[r3] = r4
            int r4 = r6 >> 8
            r4 = r4 & 255(0xff, float:3.57E-43)
            byte r4 = (byte) r4
            r0[r1] = r4
            goto L66
        L5c:
            byte r4 = (byte) r6
            r0[r3] = r4
            byte r4 = (byte) r7
            r0[r1] = r4
            goto L66
        L63:
            byte r4 = (byte) r6
            r0[r3] = r4
        L66:
            com.yucheng.ycbtsdk.core.YCBTClientImpl r4 = com.yucheng.ycbtsdk.core.YCBTClientImpl.getInstance()
            r5 = 3587(0xe03, float:5.026E-42)
            r4.sendSingleData2Device(r5, r0, r3, r8)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.yucheng.ycbtsdk.YCBTClient.dataSetting(int, int, int, int, com.yucheng.ycbtsdk.response.BleDataResponse):void");
    }

    public static void deleteCustomizeData(int i2, int i3, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(3445, new byte[]{3, (byte) i2, (byte) i3}, 2, bleDataResponse);
    }

    public static void deleteHealthHistoryData(int i2, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendDataType2Device(i2, 3, new byte[]{2}, 2, bleDataResponse);
    }

    public static void deleteHistoryListData(int i2, int i3, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendDataType2Device(Constants.DATATYPE.Collect_DeleteIndex, 13, new byte[]{(byte) i2, (byte) (i3 & 255), (byte) ((i3 >> 8) & 255), 0, 0}, 1, bleDataResponse);
    }

    public static void deleteHistoryListData(int i2, long j2, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendDataType2Device(Constants.DATATYPE.Collect_DeleteTimestamp, 13, new byte[]{(byte) i2, (byte) (j2 & 255), (byte) ((j2 >> 8) & 255), (byte) ((j2 >> 16) & 255), (byte) ((j2 >> 24) & 255)}, 1, bleDataResponse);
    }

    public static void deviceToApp(BleDeviceToAppDataResponse bleDeviceToAppDataResponse) {
        YCBTClientImpl.getInstance().registerRealTypeCallBack(bleDeviceToAppDataResponse);
    }

    public static void disconnectBT() {
        BleHelper.getHelper().disconnectA2dp();
    }

    public static void disconnectBle() {
        YCBTClientImpl.getInstance().disconnectBle();
    }

    public static void electricGuantityMonitoring(int i2, int i3, int i4, BleDataResponse bleDataResponse) {
        if (i2 == 1) {
            YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.ElectricGuantityMonitoring, new byte[]{(byte) i2, (byte) i3, (byte) i4, (byte) ((i4 >> 8) & 255)}, 2, bleDataResponse);
            return;
        }
        if (i2 == 2) {
            YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.ElectricGuantityMonitoring, new byte[]{(byte) i2, (byte) i3}, 2, bleDataResponse);
        } else if (i2 == 3) {
            YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.ElectricGuantityMonitoring, new byte[]{(byte) i2}, 2, bleDataResponse);
        } else if (i2 == 4) {
            YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.ElectricGuantityMonitoring, new byte[]{(byte) i2}, 2, bleDataResponse);
        }
    }

    public static void exitScanDevice() {
        stopScanBle();
        setmBleConnectResponse(null);
        Reconnect.getInstance().setReconnect(true);
    }

    public static void getALiIOTActivationState(BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.GetALiIOTActivationState, new byte[0], 2, bleDataResponse);
    }

    public static int getAlarmCount() {
        return DeviceSupportFunctionUtil.alarmCount();
    }

    public static void getAllRealDataFromDevice(BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.GetAllRealDataFromDevice, new byte[0], 2, bleDataResponse);
    }

    public static boolean getAuthPass() {
        return YCBTClientImpl.getInstance().isForceOta ? WatchManager.getInstance().isAuthPass() : WatchManager.getInstance().isAuthPass() && (WatchManager.getInstance().isInit() || WatchManager.getInstance().isRcspInit());
    }

    public static String getBindDeviceMac() {
        return SPUtil.getBindedDeviceMac();
    }

    public static String getBindDeviceName() {
        return SPUtil.getBindedDeviceName();
    }

    public static String getBindDeviceVersion() {
        return SPUtil.getBindDeviceVersion();
    }

    public static String getBloodSugarVersion() {
        return SPUtil.getBloodSugarVersion();
    }

    public static void getCardInfo(int i2, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.GetCardInfo, new byte[]{(byte) i2}, 2, bleDataResponse);
    }

    public static int getChipScheme() {
        return SPUtil.getChipScheme();
    }

    public static void getChipScheme(BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(539, new byte[0], 2, bleDataResponse);
    }

    public static void getCurrentAmbientLightIntensity(BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(530, new byte[]{JSONB.Constants.BC_STR_ASCII_FIX_1, 84}, 2, bleDataResponse);
    }

    public static void getCurrentAmbientTempAndHumidity(BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.GetCurrentAmbientTempAndHumidity, new byte[]{75, 85}, 2, bleDataResponse);
    }

    public static void getCurrentSystemWorkingMode(BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(534, new byte[0], 2, bleDataResponse);
    }

    public static void getCustomizeCGM(BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.Customize_CGM, new byte[]{1}, 2, bleDataResponse);
    }

    private static String getData(String str, int i2) {
        int i3;
        int i4;
        try {
            byte[] bytes = str.substring(0, i2).getBytes("UTF-8");
            boolean z = true;
            i3 = 0;
            while (z) {
                i3++;
                try {
                    if (bytes.length >= (i2 - 1) * 3 || (i4 = i2 + i3) >= str.length()) {
                        z = false;
                    } else {
                        bytes = str.substring(0, i4).getBytes("UTF-8");
                    }
                } catch (Exception e2) {
                    e = e2;
                    e.printStackTrace();
                    return str.substring(0, (i2 + i3) - 2);
                }
            }
        } catch (Exception e3) {
            e = e3;
            i3 = 0;
        }
        return str.substring(0, (i2 + i3) - 2);
    }

    public static int getDeviceBatteryState() {
        return SPUtil.getDeviceBatteryState();
    }

    public static int getDeviceBatteryValue() {
        return SPUtil.getDeviceBatteryValue();
    }

    public static void getDeviceContacts(Context context2, BleDataResponse bleDataResponse) {
        ReadContactsTask readContactsTask = new ReadContactsTask(WatchManager.getInstance(), context2);
        readContactsTask.setListener(new SimpleTaskListener() { // from class: com.yucheng.ycbtsdk.YCBTClient.5
            final /* synthetic */ ReadContactsTask val$task;

            AnonymousClass5(ReadContactsTask readContactsTask2) {
                r2 = readContactsTask2;
            }

            @Override // com.jieli.jl_rcsp.task.SimpleTaskListener, com.jieli.jl_rcsp.task.TaskListener
            public void onBegin() {
            }

            @Override // com.jieli.jl_rcsp.task.SimpleTaskListener, com.jieli.jl_rcsp.task.TaskListener
            public void onError(int i2, String str) {
                if (BleDataResponse.this != null) {
                    HashMap hashMap = new HashMap();
                    hashMap.put("msg", str);
                    BleDataResponse.this.onDataResponse(-1, 0.0f, hashMap);
                }
            }

            @Override // com.jieli.jl_rcsp.task.SimpleTaskListener, com.jieli.jl_rcsp.task.TaskListener
            public void onFinish() {
                if (BleDataResponse.this != null) {
                    List<DeviceContacts> contacts = r2.getContacts();
                    ArrayList arrayList = new ArrayList();
                    for (DeviceContacts deviceContacts : contacts) {
                        arrayList.add(new ContactsBean(deviceContacts.getFileId(), deviceContacts.getName(), deviceContacts.getMobile()));
                    }
                    HashMap hashMap = new HashMap();
                    hashMap.put("data", arrayList);
                    BleDataResponse.this.onDataResponse(0, 0.0f, hashMap);
                }
            }
        });
        readContactsTask2.start();
        resetQueue();
    }

    public static void getDeviceInfo(BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(512, new byte[]{JSONB.Constants.BC_INT32_SHORT_MAX, 67}, 2, bleDataResponse);
    }

    public static void getDeviceLog(int i2, BleDataResponse bleDataResponse, BleRealDataResponse bleRealDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(520, new byte[]{(byte) i2}, 2, bleDataResponse);
        if (bleRealDataResponse != null) {
            YCBTClientImpl.getInstance().registerRealDataCallBack(bleRealDataResponse);
        }
    }

    public static void getDeviceName(BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(515, new byte[]{JSONB.Constants.BC_INT32_SHORT_MAX, 80}, 2, bleDataResponse);
    }

    public static void getDeviceRemindInfo(int i2, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.GetDeviceRemindInfo, new byte[]{(byte) i2}, 2, bleDataResponse);
    }

    public static void getDeviceScreenInfo(BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(523, new byte[0], 2, bleDataResponse);
    }

    public static void getDeviceSupportFunction(BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(513, new byte[]{JSONB.Constants.BC_INT32_SHORT_MAX, 70}, 2, bleDataResponse);
    }

    public static String getDeviceType() {
        return readDeviceInfo(Constants.FunctionConstant.DEVICETYPE).toString();
    }

    public static void getDeviceUserConfig(BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(519, new byte[]{67, 70}, 2, bleDataResponse);
    }

    public static void getEcgMode(BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.GetEcgMode, new byte[0], 2, bleDataResponse);
    }

    public static void getElectrodeLocationInfo(BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(522, new byte[0], 2, bleDataResponse);
    }

    public static void getEventReminderInfo(BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(538, new byte[]{1}, 2, bleDataResponse);
    }

    public static void getFileCount(BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.Collect_File_Count, new byte[1], 2, bleDataResponse);
    }

    public static void getFileData(String str, int i2, BleDataResponse bleDataResponse) {
        try {
            byte[] bArr = new byte[20];
            System.arraycopy(str.getBytes("UTF-8"), 0, bArr, 0, 16);
            System.arraycopy(ByteUtil.fromInt(i2), 0, bArr, 16, 4);
            YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.Collect_File_Content, bArr, 2, bleDataResponse);
        } catch (UnsupportedEncodingException e2) {
            throw new RuntimeException(e2);
        }
    }

    public static void getFileList(int i2, int i3, BleDataResponse bleDataResponse) {
        byte[] bArr = new byte[4];
        System.arraycopy(ByteUtil.fromInt(i2), 0, bArr, 0, 2);
        System.arraycopy(ByteUtil.fromInt(i3), 0, bArr, 2, 2);
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.Collect_File_List, bArr, 2, bleDataResponse);
    }

    public static BluetoothGatt getGatt() {
        return YCBTClientImpl.getInstance().getGatt();
    }

    public static void getHeavenEarthAndFiveElement(int i2, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.GetHeavenEarthAndFiveElement, new byte[]{(byte) i2}, 2, bleDataResponse);
    }

    public static void getHistoryOutline(BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(525, new byte[0], 2, bleDataResponse);
    }

    public static void getInsuranceRelatedInfo(int i2, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(535, new byte[]{(byte) i2}, 2, bleDataResponse);
    }

    public static void getJLLog(BleDataResponse bleDataResponse) {
        WatchManager.getInstance().getLog(bleDataResponse);
    }

    public static int[] getJlScreenSize() {
        int[] iArr = new int[2];
        ExternalFlashMsgResponse extFlashMsg = DeviceStatusManager.getInstance().getExtFlashMsg(WatchManager.getInstance().getConnectedDevice());
        if (extFlashMsg != null) {
            iArr[0] = extFlashMsg.getScreenWidth();
            iArr[1] = extFlashMsg.getScreenHeight();
        }
        return iArr;
    }

    public static void getLaserTreatmentParams(BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.GetLaserTreatmentParams, new byte[]{1}, 2, bleDataResponse);
    }

    public static String getLastBindDeviceMac() {
        return SPUtil.getLastBindedDeviceMac();
    }

    public static void getMeasurementFunction(BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.GetMeasurementFunction, new byte[]{JSONB.Constants.BC_INT32_SHORT_MAX, 70}, 2, bleDataResponse);
    }

    public static int getMtu() {
        return BleHelper.MTU;
    }

    public static void getNowStep(BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(524, new byte[0], 2, bleDataResponse);
    }

    public static void getPowerStatistics(BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.GetPowerStatistics, new byte[0], 2, bleDataResponse);
    }

    public static int getQueueSize() {
        return YCBTClientImpl.getInstance().getQueueSize();
    }

    public static void getRealBloodOxygen(BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.GetRealBloodOxygen, new byte[]{73, 83}, 2, bleDataResponse);
    }

    public static void getRealTemp(BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(526, new byte[0], 2, bleDataResponse);
    }

    public static void getScheduleInfo(BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(532, new byte[]{1}, 2, bleDataResponse);
    }

    public static void getScreenInfo(BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(527, new byte[0], 2, bleDataResponse);
    }

    public static void getScreenParameters(BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.GetScreenParameters, new byte[0], 2, bleDataResponse);
    }

    public static void getSensorSamplingInfo(int i2, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(533, new byte[]{(byte) i2}, 2, bleDataResponse);
    }

    public static void getSleepStatus(BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.GetSleepStatus, new byte[0], 2, bleDataResponse);
    }

    public static void getStatusOfManualMode(BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(537, new byte[0], 2, bleDataResponse);
    }

    public static void getThemeInfo(BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(521, new byte[0], 2, bleDataResponse);
    }

    public static void getUploadConfigurationInfoOfReminder(BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.GetUploadConfigurationInfoOfReminder, new byte[0], 2, bleDataResponse);
    }

    public static void gsensor(int i2, int i3, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.Gsensor, new byte[]{(byte) i2, (byte) i3}, 2, bleDataResponse);
    }

    public static void healthHistoryData(int i2, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendDataType2Device(i2, 3, new byte[0], 2, bleDataResponse);
    }

    public static void initClient(Context context2, boolean z) {
        initClient(context2, false, z);
    }

    public static void initClient(Context context2, boolean z, boolean z2) {
        context = context2;
        YCBTClientImpl.getInstance().init(context2, z, z2);
        YCBTLog.e("YCBTClient initClient");
    }

    public static boolean isBond() {
        return BleHelper.getHelper().isBond();
    }

    public static boolean isForceOta() {
        return YCBTClientImpl.getInstance().isForceOta;
    }

    public static boolean isJieLi() {
        return getChipScheme() == 3 || getChipScheme() == 4;
    }

    public static boolean isOta() {
        return YCBTClientImpl.getInstance().isOta;
    }

    public static boolean isScaning() {
        return BleHelper.getHelper().getScanState();
    }

    public static boolean isSupportFunction(String str) {
        return DeviceSupportFunctionUtil.isHasSupportFunction(str);
    }

    public static boolean isWatchManagerInit() {
        return WatchManager.getInstance().isInit();
    }

    public static void jieliSetDialText(int i2, int i3, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.SettingSettingCustomDial, new byte[]{(byte) i2, (byte) (i3 & 255), (byte) ((i3 >> 8) & 255), 0, 0, 0, 0}, 2, bleDataResponse);
    }

    public static void jlInstallCustomizeDial(String str, BleDataResponse bleDataResponse) {
        WatchManager.getInstance().createWatchFile(str, true, new OnFatFileProgressListener() { // from class: com.yucheng.ycbtsdk.YCBTClient.11
            AnonymousClass11() {
            }

            @Override // com.jieli.jl_fatfs.interfaces.OnFatFileProgressListener
            public void onProgress(float f2) {
                if (BleDataResponse.this != null) {
                    HashMap hashMap = new HashMap();
                    hashMap.put("progress", Float.valueOf(f2));
                    hashMap.put("dataType", Integer.valueOf(Constants.DATATYPE.WatchDialProgress));
                    BleDataResponse.this.onDataResponse(0, 0.0f, hashMap);
                }
            }

            @Override // com.jieli.jl_fatfs.interfaces.OnFatFileProgressListener
            public void onStart(String str2) {
                if (BleDataResponse.this != null) {
                    HashMap hashMap = new HashMap();
                    hashMap.put("progress", Float.valueOf(0.0f));
                    hashMap.put("dataType", Integer.valueOf(Constants.DATATYPE.WatchDialProgress));
                    BleDataResponse.this.onDataResponse(0, 0.0f, hashMap);
                }
            }

            @Override // com.jieli.jl_fatfs.interfaces.OnFatFileProgressListener
            public void onStop(int i2) {
                BleDataResponse bleDataResponse2;
                int i3;
                YCBTLog.e("jlInstallCustomizeDial result=" + i2);
                if (i2 == 0) {
                    bleDataResponse2 = BleDataResponse.this;
                    if (bleDataResponse2 == null) {
                        return;
                    } else {
                        i3 = 0;
                    }
                } else {
                    bleDataResponse2 = BleDataResponse.this;
                    if (bleDataResponse2 == null) {
                        return;
                    } else {
                        i3 = -1;
                    }
                }
                bleDataResponse2.onDataResponse(i3, 0.0f, null);
            }
        });
    }

    public static void jlSaveCustomizeDialBg(String str, String str2, BleDataResponse bleDataResponse) {
        YCBTLog.e("jl_watch_dial--inPath==" + str + HelpFormatter.DEFAULT_LONG_OPT_PREFIX + str2);
        BmpConvert bmpConvert = new BmpConvert();
        bmpConvert.bitmapConvert(WatchManager.getInstance().getDeviceInfo(WatchManager.getInstance().getConnectedDevice()).getSdkType() == 9 ? 1 : 0, str, str2, new OnConvertListener() { // from class: com.yucheng.ycbtsdk.YCBTClient.10
            final /* synthetic */ BmpConvert val$bmpConvert;

            AnonymousClass10(BmpConvert bmpConvert2) {
                r2 = bmpConvert2;
            }

            @Override // com.jieli.bmp_convert.OnConvertListener
            public void onStart(String str3) {
                YCBTLog.e("jl_watch_dial_start--path==" + str3);
            }

            @Override // com.jieli.bmp_convert.OnConvertListener
            public void onStop(boolean z, String str3) {
                if (BleDataResponse.this != null) {
                    HashMap hashMap = new HashMap();
                    hashMap.put(ClientCookie.PATH_ATTR, str3);
                    BleDataResponse.this.onDataResponse(z ? 0 : -1, 0.0f, hashMap);
                }
                BmpConvert bmpConvert2 = r2;
                if (bmpConvert2 != null) {
                    bmpConvert2.release();
                }
            }
        });
    }

    public static void jlWatchDialDelete(String str, BleDataResponse bleDataResponse) {
        YCBTLog.e("jlWatchDialDelete = " + str);
        WatchManager.getInstance().deleteWatchFile(str, new OnFatFileProgressListener() { // from class: com.yucheng.ycbtsdk.YCBTClient.8
            AnonymousClass8() {
            }

            @Override // com.jieli.jl_fatfs.interfaces.OnFatFileProgressListener
            public void onProgress(float f2) {
            }

            @Override // com.jieli.jl_fatfs.interfaces.OnFatFileProgressListener
            public void onStart(String str2) {
            }

            @Override // com.jieli.jl_fatfs.interfaces.OnFatFileProgressListener
            public void onStop(int i2) {
                YCBTLog.e("jlWatchDialDelete result=" + i2);
                BleDataResponse bleDataResponse2 = BleDataResponse.this;
                if (bleDataResponse2 != null) {
                    bleDataResponse2.onDataResponse(i2, 0.0f, null);
                }
            }
        });
    }

    public static void jlWatchDialDownload(String str, boolean z, BleDataResponse bleDataResponse) {
        WatchManager.getInstance().createWatchFile(str, z, new OnFatFileProgressListener() { // from class: com.yucheng.ycbtsdk.YCBTClient.6
            AnonymousClass6() {
            }

            @Override // com.jieli.jl_fatfs.interfaces.OnFatFileProgressListener
            public void onProgress(float f2) {
                if (BleDataResponse.this != null) {
                    HashMap hashMap = new HashMap();
                    hashMap.put("progress", Float.valueOf(f2));
                    hashMap.put("dataType", Integer.valueOf(Constants.DATATYPE.WatchDialProgress));
                    BleDataResponse.this.onDataResponse(0, 0.0f, hashMap);
                }
            }

            @Override // com.jieli.jl_fatfs.interfaces.OnFatFileProgressListener
            public void onStart(String str2) {
                if (BleDataResponse.this != null) {
                    HashMap hashMap = new HashMap();
                    hashMap.put("progress", Float.valueOf(0.0f));
                    hashMap.put("dataType", Integer.valueOf(Constants.DATATYPE.WatchDialProgress));
                    BleDataResponse.this.onDataResponse(0, 0.0f, hashMap);
                }
            }

            @Override // com.jieli.jl_fatfs.interfaces.OnFatFileProgressListener
            public void onStop(int i2) {
                BleDataResponse bleDataResponse2 = BleDataResponse.this;
                if (bleDataResponse2 != null) {
                    if (i2 == 0) {
                        i2 = 0;
                    }
                    bleDataResponse2.onDataResponse(i2, 0.0f, null);
                }
            }
        });
    }

    public static void jlWatchDialSetCurrent(String str, BleDataResponse bleDataResponse) {
        WatchManager.getInstance().setCurrentWatchInfo(str, new OnWatchOpCallback<FatFile>() { // from class: com.yucheng.ycbtsdk.YCBTClient.9
            AnonymousClass9() {
            }

            @Override // com.jieli.jl_rcsp.interfaces.watch.OnWatchOpCallback
            public void onFailed(BaseError baseError) {
                YCBTLog.e("jlWatchDialSetCurrent error.getMessage()" + baseError.getMessage() + "  error.getCode()" + baseError.getCode());
                BleDataResponse.this.onDataResponse(-1, 0.0f, null);
            }

            @Override // com.jieli.jl_rcsp.interfaces.watch.OnWatchOpCallback
            public void onSuccess(FatFile fatFile) {
                YCBTLog.e("jlWatchDialSetCurrent result" + new Gson().toJson(fatFile));
                if (BleDataResponse.this != null) {
                    HashMap hashMap = new HashMap();
                    if (fatFile != null) {
                        hashMap.put("data", fatFile.toString());
                        BleDataResponse.this.onDataResponse(0, 0.0f, hashMap);
                    }
                }
            }
        });
    }

    public static void newSettingTemperatureAlarm(boolean z, int i2, int i3, int i4, int i5, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.SettingTemperatureAlarm, new byte[]{z ? (byte) 1 : (byte) 0, (byte) i2, (byte) i3, (byte) i4, (byte) i5}, 2, bleDataResponse);
    }

    public static void notifyDevice(BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.AppSendNotifyToDevice, new byte[]{0}, 2, bleDataResponse);
    }

    public static void oneKeyBackground(int i2, int i3, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.OneKeyBackground, new byte[]{(byte) i2, (byte) i3}, 2, bleDataResponse);
    }

    public static void openFactory(boolean z, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.OpenFactory, new byte[]{1, 1, z ? (byte) 1 : (byte) 0}, 2, bleDataResponse);
    }

    public static void otaDownload(int i2, int i3, byte[] bArr, BleDataResponse bleDataResponse) {
        int length = bArr.length;
        int crc16_compute = ByteUtil.crc16_compute(bArr, bArr.length);
        YCBTClientImpl.setOtaDownloadData(bArr);
        YCBTClientImpl.getInstance().sendSingleData2Device(2560, new byte[]{(byte) i2, (byte) length, (byte) ((length >> 8) & 255), (byte) ((length >> 16) & 255), (byte) ((length >> 24) & 255), (byte) i3, (byte) crc16_compute, (byte) ((crc16_compute >> 8) & 255)}, 2, bleDataResponse);
    }

    public static void otaUIBlock(byte[] bArr, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(32258, bArr, 2, bleDataResponse);
    }

    public static void otaUIBlockCheck(int i2, int i3, int i4, BleDataResponse bleDataResponse) {
        byte[] bArr = new byte[8];
        System.arraycopy(ByteUtil.fromInt(i2), 0, bArr, 0, 4);
        System.arraycopy(ByteUtil.fromInt(i3), 0, bArr, 4, 2);
        System.arraycopy(ByteUtil.fromInt(i4), 0, bArr, 6, 2);
        YCBTClientImpl.getInstance().sendSingleData2Device(32259, bArr, 2, bleDataResponse);
    }

    public static void otaUIFileInfo(int i2, int i3, int i4, int i5, int i6, BleDataResponse bleDataResponse) {
        byte[] bArr = new byte[18];
        System.arraycopy(ByteUtil.fromInt(i2), 0, bArr, 0, 4);
        System.arraycopy(ByteUtil.fromInt(i3), 0, bArr, 4, 4);
        System.arraycopy(ByteUtil.fromInt(i4), 0, bArr, 8, 4);
        System.arraycopy(ByteUtil.fromInt(i5), 0, bArr, 12, 4);
        System.arraycopy(ByteUtil.fromInt(i6), 0, bArr, 16, 2);
        YCBTClientImpl.getInstance().sendSingleData2Device(32257, bArr, 2, bleDataResponse);
    }

    public static void otaUIGetBreakInfo(BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(32256, new byte[]{0}, 2, bleDataResponse);
    }

    public static void powerMonitoringDataUploadFormat(int i2, int i3, int i4, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(3445, new byte[]{(byte) i2}, 2, bleDataResponse);
    }

    public static Object readDeviceInfo(String str) {
        return DeviceSupportFunctionUtil.readDeviceInfo(str);
    }

    public static void reconnectBle(BleConnectResponse bleConnectResponse) {
        String bindedDeviceMac = SPUtil.getBindedDeviceMac();
        String bindedDeviceName = SPUtil.getBindedDeviceName();
        if (TextUtils.isEmpty(bindedDeviceMac)) {
            return;
        }
        connectBle(bindedDeviceMac, bindedDeviceName, bleConnectResponse);
    }

    public static void registerBleStateChange(BleConnectResponse bleConnectResponse) {
        YCBTClientImpl.getInstance().registerBleStateChangeCallBack(bleConnectResponse);
    }

    public static void resetBond() {
        SPUtil.put(Constants.SharedKey.Is_Create_Bond, Boolean.FALSE);
        BleHelper.getHelper().disconnectA2dp();
    }

    public static void resetQueue() {
        YCBTClientImpl.getInstance().resetQueue();
    }

    public static void selfInspection(int i2, int i3, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.SelfInspection, new byte[]{(byte) i2, (byte) i3, (byte) ((i3 >> 8) & 255)}, 2, bleDataResponse);
    }

    public static void sendALIDataToDevice(byte[] bArr, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.ALIDATA, bArr, 2, bleDataResponse);
    }

    public static void sendDomain(String str, BleDataResponse bleDataResponse) {
        try {
            YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.AppSendDomain, str.getBytes("UTF-8"), 2, bleDataResponse);
        } catch (UnsupportedEncodingException e2) {
            e2.printStackTrace();
        }
    }

    public static void sendJLDataToDevice(byte[] bArr, boolean z) {
        YCBTClientImpl.getInstance().sendSingleData2Device(z ? Constants.DATATYPE.JLOTADATA : Constants.DATATYPE.JLDATA, bArr, 2, null);
    }

    public static void sendWarningBackgroundLine(int i2, byte[] bArr, BleDataResponse bleDataResponse) {
        byte[] bArr2 = new byte[bArr.length + 1];
        bArr2[0] = (byte) i2;
        System.arraycopy(bArr, 0, bArr2, 1, bArr.length);
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.AppSendBackgroundLine, bArr2, 2, bleDataResponse);
    }

    public static void setAuthPass(BleDataResponse bleDataResponse) {
        WatchManager.getInstance().setReAuthPass(bleDataResponse);
    }

    public static void setBonding(boolean z) {
        YCBTClientImpl.getInstance().isBonding = z;
    }

    public static void setDialCustomize(Context context2, String str, String str2, int i2, String str3, int i3, int i4, int i5, int i6, boolean z, DialUtils.DialProgressListener dialProgressListener) {
        DialUtils.getInstance().setDialCustomize(context2, str, str2, i2, str3, i3, i4, i5, i6, z, dialProgressListener);
    }

    public static void setMtu(int i2) {
        BleHelper.getHelper().setMTU(i2);
    }

    public static void setOta(boolean z) {
        YCBTClientImpl.getInstance().setOta(z);
    }

    public static void setReconnect(boolean z) {
        Reconnect.getInstance().setReconnect(z);
    }

    public static void setSingleMeasurementFunction(int i2, boolean z, BleDataResponse bleDataResponse) {
        String obj = SPUtil.get(Constants.SharedKey.Function_Str, "00000000").toString();
        char[] charArray = obj.toCharArray();
        charArray[(obj.length() - 1) - i2] = z ? '1' : '0';
        String str = new String(charArray);
        SPUtil.put(Constants.SharedKey.Function_Str, str);
        YCBTLog.e("功能设置：".concat(str));
        byte[] bArr = new byte[9];
        bArr[0] = (byte) Integer.parseInt(Long.toHexString(Long.parseLong(str, 2)), 16);
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.SettingMeasurementFunction, bArr, 2, bleDataResponse);
    }

    public static void setTheBenchmarkDeviceValue(int i2, int i3, int i4, BleDataResponse bleDataResponse) {
        byte[] bArr = new byte[15];
        if (i2 == 0) {
            bArr[1] = (byte) (i3 & 255);
            bArr[2] = (byte) ((i3 >> 8) & 255);
        }
        bArr[0] = (byte) i2;
        bArr[1] = (byte) i3;
        bArr[2] = (byte) i4;
        YCSendBean yCSendBean = new YCSendBean(bArr, 2, bleDataResponse);
        yCSendBean.dataType = Constants.DATATYPE.SetTheBenchmarkDeviceValue;
        yCSendBean.groupType = 1;
        yCSendBean.dataSendFinish = true;
        YCBTClientImpl.getInstance().pushQueue(yCSendBean);
    }

    public static void setTheBenchmarkDeviceValueStep(int i2, BleDataResponse bleDataResponse) {
        byte[] bArr = new byte[15];
        bArr[0] = 0;
        bArr[1] = (byte) (i2 & 255);
        bArr[2] = (byte) ((i2 >> 8) & 255);
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.SetTheBenchmarkDeviceValue, bArr, 2, bleDataResponse);
    }

    public static void setWitOnOff(int i2, int i3, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.Customize_Intelligent_Functions, new byte[]{1, (byte) i2, (byte) i3}, 2, bleDataResponse);
    }

    public static void setmBleConnectResponse(BleConnectResponse bleConnectResponse) {
        YCBTClientImpl.getInstance().setmBleConnectResponse(bleConnectResponse);
    }

    public static void settingAccidentMode(boolean z, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.SettingAccidentMode, new byte[]{z ? (byte) 1 : (byte) 0}, 2, bleDataResponse);
    }

    public static void settingAddAlarm(int i2, int i3, int i4, int i5, int i6, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(257, new byte[]{1, (byte) i2, (byte) i3, (byte) i4, (byte) i5, (byte) i6}, 2, bleDataResponse);
    }

    public static void settingAirPumpFrequency(int i2, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(309, new byte[]{(byte) i2, (byte) ((i2 >> 8) & 255), (byte) ((i2 >> 16) & 255), (byte) ((i2 >> 24) & 255)}, 2, bleDataResponse);
    }

    public static void settingAmbientLight(boolean z, int i2, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.SettingAmbientLight, new byte[]{z ? (byte) 1 : (byte) 0, (byte) i2}, 2, bleDataResponse);
    }

    public static void settingAmbientTemperatureAndHumidity(boolean z, int i2, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.SettingAmbientTemperatureAndHumidity, new byte[]{z ? (byte) 1 : (byte) 0, (byte) i2}, 2, bleDataResponse);
    }

    public static void settingAntiLose(int i2, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(262, new byte[]{(byte) i2}, 2, bleDataResponse);
    }

    public static void settingAppSystem(int i2, String str, BleDataResponse bleDataResponse) {
        byte[] bArr;
        int i3;
        if (TextUtils.isEmpty(str)) {
            bArr = null;
            i3 = 0;
        } else {
            bArr = str.getBytes();
            i3 = bArr.length;
        }
        byte[] bArr2 = new byte[i3 + 1];
        bArr2[0] = (byte) i2;
        if (i3 != 0) {
            System.arraycopy(bArr, 0, bArr2, 1, i3);
        }
        YCBTClientImpl.getInstance().sendSingleData2Device(265, bArr2, 2, bleDataResponse);
    }

    public static void settingAutomaticMeasurementTime(int i2, int i3, int i4, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(320, new byte[]{(byte) i2, (byte) i3, (byte) i4}, 2, bleDataResponse);
    }

    public static void settingBloodAlarm(int i2, int i3, int i4, int i5, int i6, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(312, new byte[]{(byte) i2, (byte) i3, (byte) i4, (byte) i5, (byte) i6}, 2, bleDataResponse);
    }

    public static void settingBloodOxygenAlarm(int i2, int i3, int i4, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(313, new byte[]{(byte) i2, (byte) i3, (byte) i4}, 2, bleDataResponse);
    }

    public static void settingBloodOxygenAlarm(int i2, int i3, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(313, new byte[]{(byte) i2, (byte) i3, 0}, 2, bleDataResponse);
    }

    public static void settingBloodOxygenModeMonitor(boolean z, int i2, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.SettingBloodOxygenModeMonitor, new byte[]{z ? (byte) 1 : (byte) 0, (byte) i2}, 2, bleDataResponse);
    }

    public static void settingBloodRange(int i2, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.SettingBloodRange, new byte[]{(byte) i2}, 2, bleDataResponse);
    }

    public static void settingBloodSugarAlarm(int i2, int i3, int i4, int i5, int i6, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.SettingBloodSugarAlarm, new byte[]{(byte) i2, (byte) i3, (byte) i4, (byte) i5, (byte) i6, 0, 0, 0, 0}, 2, bleDataResponse);
    }

    public static void settingBluetoothBroadcastInterval(int i2, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(300, new byte[]{(byte) (i2 & 255), (byte) ((i2 >> 8) & 255)}, 2, bleDataResponse);
    }

    public static void settingBluetoothTransmittingPower(int i2, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(301, new byte[]{(byte) i2}, 2, bleDataResponse);
    }

    public static void settingBraceletStatusAlert(boolean z, int i2, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.SettingBraceletStatusAlert, new byte[]{z ? (byte) 1 : (byte) 0, (byte) i2}, 2, bleDataResponse);
    }

    public static void settingConfigInDifWorkingModes(int i2, int i3, int i4, int i5, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(305, new byte[]{(byte) i2, (byte) i3, (byte) i4, (byte) ((i4 >> 8) & 255), (byte) i5, (byte) ((i5 >> 8) & 255)}, 2, bleDataResponse);
    }

    public static void settingDataCollect(int i2, int i3, int i4, int i5, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(283, new byte[]{(byte) (i2 & 255), (byte) (i3 & 255), (byte) (i4 & 255), (byte) ((i4 >> 8) & 255), (byte) (i5 & 255), (byte) ((i5 >> 8) & 255)}, 2, bleDataResponse);
    }

    public static void settingDeleteAlarm(int i2, int i3, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(257, new byte[]{2, (byte) i2, (byte) i3}, 2, bleDataResponse);
    }

    public static void settingDeviceMac(String str, BleDataResponse bleDataResponse) {
        if (str == null) {
            return;
        }
        if (str.contains(CertificateUtil.DELIMITER)) {
            str = str.replace(CertificateUtil.DELIMITER, "");
        }
        if (str.length() != 12) {
            return;
        }
        try {
            YCBTClientImpl.getInstance().sendSingleData2Device(308, new byte[]{(byte) Integer.parseInt(str.substring(10, 12), 16), (byte) Integer.parseInt(str.substring(8, 10), 16), (byte) Integer.parseInt(str.substring(6, 8), 16), (byte) Integer.parseInt(str.substring(4, 6), 16), (byte) Integer.parseInt(str.substring(2, 4), 16), (byte) Integer.parseInt(str.substring(0, 2), 16)}, 2, bleDataResponse);
        } catch (Exception e2) {
            e2.printStackTrace();
        }
    }

    public static void settingDeviceName(String str, BleDataResponse bleDataResponse) {
        try {
            YCBTClientImpl.getInstance().sendSingleData2Device(279, str.getBytes("UTF-8"), 2, bleDataResponse);
        } catch (UnsupportedEncodingException e2) {
            e2.printStackTrace();
        }
    }

    public static void settingDisplayBrightness(int i2, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(276, new byte[]{(byte) i2}, 2, bleDataResponse);
    }

    public static void settingEmergencyContacts(List<String> list, BleDataResponse bleDataResponse) {
        if (list.isEmpty()) {
            return;
        }
        int size = list.size();
        ArrayList arrayList = new ArrayList();
        int i2 = 1;
        for (int i3 = 0; i3 < list.size(); i3++) {
            byte[] bytes = list.get(i3).getBytes(StandardCharsets.UTF_8);
            i2 += bytes.length;
            arrayList.add(bytes);
        }
        byte[] bArr = {0};
        byte[] bytes2 = ",".getBytes(StandardCharsets.UTF_8);
        byte[] bArr2 = new byte[i2 + (bytes2.length * (size - 1)) + 1];
        bArr2[0] = (byte) size;
        int i4 = 1;
        for (int i5 = 0; i5 < arrayList.size(); i5++) {
            byte[] bArr3 = (byte[]) arrayList.get(i5);
            System.arraycopy(bArr3, 0, bArr2, i4, bArr3.length);
            i4 += bArr3.length;
            if (i5 != arrayList.size() - 1) {
                System.arraycopy(bytes2, 0, bArr2, i4, bytes2.length);
                i4 += bytes2.length;
            }
        }
        System.arraycopy(bArr, 0, bArr2, i4, 1);
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.SettingEmergencyContacts, bArr2, 2, bleDataResponse);
    }

    public static void settingEventReminder(int i2, int i3, int i4, int i5, int i6, int i7, int i8, int i9, String str, BleDataResponse bleDataResponse) {
        int i10;
        byte[] bArr = null;
        if (i5 != 1 || str == null) {
            i10 = 0;
        } else {
            try {
                bArr = str.getBytes("UTF-8");
                i10 = bArr.length;
            } catch (Exception e2) {
                e2.printStackTrace();
                i10 = 0;
            }
        }
        if (i10 > 12) {
            return;
        }
        byte[] bArr2 = new byte[i10 + 8];
        byte b2 = (byte) i2;
        bArr2[0] = b2;
        bArr2[1] = (byte) i3;
        bArr2[2] = (byte) i4;
        bArr2[3] = (byte) i5;
        bArr2[4] = (byte) i6;
        bArr2[5] = (byte) i7;
        bArr2[6] = (byte) i8;
        bArr2[7] = (byte) i9;
        bArr2[0] = b2;
        if (bArr != null) {
            System.arraycopy(bArr, 0, bArr2, 8, i10);
        }
        YCBTClientImpl.getInstance().sendSingleData2Device(303, bArr2, 2, bleDataResponse);
    }

    public static void settingEventReminderSwitch(int i2, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(304, new byte[]{(byte) i2}, 2, bleDataResponse);
    }

    public static void settingExerciseHeartRateZone(int i2, int i3, int i4, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(302, new byte[]{(byte) i2, (byte) i3, (byte) i4}, 2, bleDataResponse);
    }

    public static void settingFindPhone(int i2, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(269, new byte[]{(byte) i2}, 2, bleDataResponse);
    }

    public static void settingGetAllAlarm(BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(257, new byte[]{0}, 2, bleDataResponse);
    }

    public static void settingGoal(int i2, int i3, int i4, int i5, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(258, new byte[]{(byte) i2, (byte) (i3 & 255), (byte) ((i3 >> 8) & 255), (byte) ((i3 >> 16) & 255), (byte) ((i3 >> 24) & 255), (byte) i4, (byte) i5}, 2, bleDataResponse);
    }

    public static void settingHRVMonitor(int i2, int i3, int i4, int i5, int i6, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.SettingHRVMonitor, new byte[]{(byte) i2, (byte) i3, (byte) i4, (byte) i5, (byte) i6}, 2, bleDataResponse);
    }

    public static void settingHandWear(int i2, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(264, new byte[]{(byte) i2}, 2, bleDataResponse);
    }

    public static void settingHeartAlarm(int i2, int i3, int i4, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(267, new byte[]{(byte) i2, (byte) i3, (byte) i4}, 2, bleDataResponse);
    }

    public static void settingHeartAlarmDuration(int i2, int i3, int i4, int i5, int i6, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(267, new byte[]{(byte) i2, (byte) i3, (byte) i4, (byte) i5, (byte) i6}, 2, bleDataResponse);
    }

    public static void settingHeartMonitor(int i2, int i3, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(268, new byte[]{(byte) i2, (byte) i3}, 2, bleDataResponse);
    }

    public static void settingInsuranceSwitch(int i2, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(306, new byte[]{(byte) i2}, 2, bleDataResponse);
    }

    public static void settingLanguage(int i2, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(274, new byte[]{(byte) i2}, 2, bleDataResponse);
    }

    public static void settingLaserTreatmentParams(int i2, int i3, int i4, int i5, int i6, int i7, int i8, int i9, int i10, int i11, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(315, new byte[]{(byte) i2, (byte) i3, (byte) i4, (byte) i5, (byte) i6, (byte) i7, (byte) i8, (byte) i9, (byte) ((i9 >> 8) & 255), (byte) i10, (byte) i11}, 2, bleDataResponse);
    }

    public static void settingLatitudeAndLongitude(int i2, int i3, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(311, new byte[]{(byte) i2, (byte) ((i2 >> 8) & 255), (byte) ((i2 >> 16) & 255), (byte) ((i2 >> 24) & 255), (byte) i3, (byte) ((i3 >> 8) & 255), (byte) ((i3 >> 16) & 255), (byte) ((i3 >> 24) & 255), 0, 0, 0, 0}, 2, bleDataResponse);
    }

    public static void settingLongsite(int i2, int i3, int i4, int i5, int i6, int i7, int i8, int i9, int i10, int i11, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(261, new byte[]{(byte) i2, (byte) i3, (byte) i4, (byte) i5, (byte) i6, (byte) i7, (byte) i8, (byte) i9, (byte) i10, (byte) i11}, 2, bleDataResponse);
    }

    public static void settingLunchDoNotDisturbMode(int i2, int i3, int i4, int i5, int i6, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(307, new byte[]{(byte) i2, (byte) i3, (byte) i4, (byte) i5, (byte) i6}, 2, bleDataResponse);
    }

    public static void settingMainTheme(int i2, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(281, new byte[]{(byte) i2}, 2, bleDataResponse);
    }

    public static void settingModfiyAlarm(int i2, int i3, int i4, int i5, int i6, int i7, int i8, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(257, new byte[]{3, (byte) i2, (byte) i3, (byte) i4, (byte) i5, (byte) i6, (byte) i7, (byte) i8}, 2, bleDataResponse);
    }

    public static void settingNotDisturb(int i2, int i3, int i4, int i5, int i6, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(271, new byte[]{(byte) i2, (byte) i3, (byte) i4, (byte) i5, (byte) i6}, 2, bleDataResponse);
    }

    public static void settingNotify(int i2, int i3, int i4, int i5, BleDataResponse bleDataResponse) {
        byte[] bArr = new byte[11];
        bArr[0] = (byte) i2;
        bArr[1] = (byte) i3;
        bArr[2] = (byte) i4;
        bArr[3] = (byte) i5;
        YCBTClientImpl.getInstance().sendSingleData2Device(266, bArr, 2, bleDataResponse);
    }

    public static void settingPpgCollect(int i2, int i3, int i4, BleDataResponse bleDataResponse) {
        settingDataCollect(i2, 0, i3, i4, bleDataResponse);
    }

    public static void settingRaiseScreen(int i2, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(275, new byte[]{(byte) i2}, 2, bleDataResponse);
    }

    /* JADX WARN: Removed duplicated region for block: B:6:0x0032  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public static void settingRegularReminder(int r3, int r4, int r5, int r6, int r7, int r8, int r9, java.lang.String r10, com.yucheng.ycbtsdk.response.BleDataResponse r11) {
        /*
            r0 = 7
            r1 = 0
            if (r10 == 0) goto L11
            java.lang.String r2 = "UTF-8"
            byte[] r1 = r10.getBytes(r2)     // Catch: java.lang.Exception -> Ld
            int r10 = r1.length     // Catch: java.lang.Exception -> Ld
            int r10 = r10 + r0
            goto L12
        Ld:
            r10 = move-exception
            r10.printStackTrace()
        L11:
            r10 = r0
        L12:
            byte[] r10 = new byte[r10]
            byte r3 = (byte) r3
            r2 = 0
            r10[r2] = r3
            byte r3 = (byte) r4
            r4 = 1
            r10[r4] = r3
            byte r3 = (byte) r5
            r4 = 2
            r10[r4] = r3
            byte r3 = (byte) r6
            r5 = 3
            r10[r5] = r3
            byte r3 = (byte) r7
            r5 = 4
            r10[r5] = r3
            byte r3 = (byte) r8
            r5 = 5
            r10[r5] = r3
            byte r3 = (byte) r9
            r5 = 6
            r10[r5] = r3
            if (r1 == 0) goto L36
            int r3 = r1.length
            java.lang.System.arraycopy(r1, r2, r10, r0, r3)
        L36:
            com.yucheng.ycbtsdk.core.YCBTClientImpl r3 = com.yucheng.ycbtsdk.core.YCBTClientImpl.getInstance()
            r5 = 317(0x13d, float:4.44E-43)
            r3.sendSingleData2Device(r5, r10, r4, r11)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.yucheng.ycbtsdk.YCBTClient.settingRegularReminder(int, int, int, int, int, int, int, java.lang.String, com.yucheng.ycbtsdk.response.BleDataResponse):void");
    }

    public static void settingRespiratoryRateAlarm(int i2, int i3, int i4, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(318, new byte[]{(byte) i2, (byte) i3, (byte) i4}, 2, bleDataResponse);
    }

    public static void settingRestoreFactory(BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(270, new byte[]{82, 83, 89, 83}, 2, bleDataResponse);
    }

    public static void settingRingSizeAndColor(int i2, int i3, int i4, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.SettingRingSizeAndColor, new byte[]{(byte) i2, (byte) i3, (byte) i4}, 2, bleDataResponse);
    }

    /* JADX WARN: Removed duplicated region for block: B:16:0x0040 A[Catch: Exception -> 0x009f, TryCatch #0 {Exception -> 0x009f, blocks: (B:18:0x0002, B:20:0x0008, B:3:0x0010, B:6:0x0042, B:8:0x0091, B:9:0x0095, B:16:0x0040), top: B:17:0x0002 }] */
    /* JADX WARN: Removed duplicated region for block: B:5:0x003e  */
    /* JADX WARN: Removed duplicated region for block: B:8:0x0091 A[Catch: Exception -> 0x009f, TryCatch #0 {Exception -> 0x009f, blocks: (B:18:0x0002, B:20:0x0008, B:3:0x0010, B:6:0x0042, B:8:0x0091, B:9:0x0095, B:16:0x0040), top: B:17:0x0002 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public static void settingScheduleModification(int r5, int r6, int r7, int r8, int r9, java.lang.String r10, int r11, java.lang.String r12, com.yucheng.ycbtsdk.response.BleDataResponse r13) {
        /*
            if (r12 == 0) goto Lf
            int r0 = r12.length()     // Catch: java.lang.Exception -> L9f
            if (r0 <= 0) goto Lf
            java.lang.String r0 = "UTF-8"
            byte[] r12 = r12.getBytes(r0)     // Catch: java.lang.Exception -> L9f
            goto L10
        Lf:
            r12 = 0
        L10:
            java.text.SimpleDateFormat r0 = new java.text.SimpleDateFormat     // Catch: java.lang.Exception -> L9f
            java.lang.String r1 = "yyyy-MM-dd HH:mm:ss"
            r0.<init>(r1)     // Catch: java.lang.Exception -> L9f
            java.util.Date r10 = r0.parse(r10)     // Catch: java.lang.Exception -> L9f
            long r0 = r10.getTime()     // Catch: java.lang.Exception -> L9f
            r2 = 1000(0x3e8, double:4.94E-321)
            long r0 = r0 / r2
            r2 = 946684800(0x386d4380, double:4.67724437E-315)
            long r0 = r0 - r2
            java.util.TimeZone r10 = java.util.TimeZone.getDefault()     // Catch: java.lang.Exception -> L9f
            long r2 = java.lang.System.currentTimeMillis()     // Catch: java.lang.Exception -> L9f
            int r10 = r10.getOffset(r2)     // Catch: java.lang.Exception -> L9f
            int r10 = r10 / 1000
            long r2 = (long) r10     // Catch: java.lang.Exception -> L9f
            long r0 = r0 + r2
            java.lang.Long r10 = java.lang.Long.valueOf(r0)     // Catch: java.lang.Exception -> L9f
            r0 = 10
            if (r12 != 0) goto L40
            r1 = r0
            goto L42
        L40:
            int r1 = r12.length     // Catch: java.lang.Exception -> L9f
            int r1 = r1 + r0
        L42:
            byte[] r1 = new byte[r1]     // Catch: java.lang.Exception -> L9f
            byte r5 = (byte) r5     // Catch: java.lang.Exception -> L9f
            r2 = 0
            r1[r2] = r5     // Catch: java.lang.Exception -> L9f
            byte r5 = (byte) r6     // Catch: java.lang.Exception -> L9f
            r6 = 1
            r1[r6] = r5     // Catch: java.lang.Exception -> L9f
            byte r5 = (byte) r7     // Catch: java.lang.Exception -> L9f
            r6 = 2
            r1[r6] = r5     // Catch: java.lang.Exception -> L9f
            byte r5 = (byte) r8     // Catch: java.lang.Exception -> L9f
            r7 = 3
            r1[r7] = r5     // Catch: java.lang.Exception -> L9f
            byte r5 = (byte) r9     // Catch: java.lang.Exception -> L9f
            r7 = 4
            r1[r7] = r5     // Catch: java.lang.Exception -> L9f
            long r7 = r10.longValue()     // Catch: java.lang.Exception -> L9f
            r3 = 255(0xff, double:1.26E-321)
            long r7 = r7 & r3
            int r5 = (int) r7     // Catch: java.lang.Exception -> L9f
            byte r5 = (byte) r5     // Catch: java.lang.Exception -> L9f
            r7 = 5
            r1[r7] = r5     // Catch: java.lang.Exception -> L9f
            long r7 = r10.longValue()     // Catch: java.lang.Exception -> L9f
            r5 = 8
            long r7 = r7 >> r5
            long r7 = r7 & r3
            int r7 = (int) r7     // Catch: java.lang.Exception -> L9f
            byte r7 = (byte) r7     // Catch: java.lang.Exception -> L9f
            r8 = 6
            r1[r8] = r7     // Catch: java.lang.Exception -> L9f
            long r7 = r10.longValue()     // Catch: java.lang.Exception -> L9f
            r9 = 16
            long r7 = r7 >> r9
            long r7 = r7 & r3
            int r7 = (int) r7     // Catch: java.lang.Exception -> L9f
            byte r7 = (byte) r7     // Catch: java.lang.Exception -> L9f
            r8 = 7
            r1[r8] = r7     // Catch: java.lang.Exception -> L9f
            long r7 = r10.longValue()     // Catch: java.lang.Exception -> L9f
            r9 = 24
            long r7 = r7 >> r9
            long r7 = r7 & r3
            int r7 = (int) r7     // Catch: java.lang.Exception -> L9f
            byte r7 = (byte) r7     // Catch: java.lang.Exception -> L9f
            r1[r5] = r7     // Catch: java.lang.Exception -> L9f
            byte r5 = (byte) r11     // Catch: java.lang.Exception -> L9f
            r7 = 9
            r1[r7] = r5     // Catch: java.lang.Exception -> L9f
            if (r12 == 0) goto L95
            int r5 = r12.length     // Catch: java.lang.Exception -> L9f
            java.lang.System.arraycopy(r12, r2, r1, r0, r5)     // Catch: java.lang.Exception -> L9f
        L95:
            com.yucheng.ycbtsdk.core.YCBTClientImpl r5 = com.yucheng.ycbtsdk.core.YCBTClientImpl.getInstance()     // Catch: java.lang.Exception -> L9f
            r7 = 295(0x127, float:4.13E-43)
            r5.sendSingleData2Device(r7, r1, r6, r13)     // Catch: java.lang.Exception -> L9f
            goto La3
        L9f:
            r5 = move-exception
            r5.printStackTrace()
        La3:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.yucheng.ycbtsdk.YCBTClient.settingScheduleModification(int, int, int, int, int, java.lang.String, int, java.lang.String, com.yucheng.ycbtsdk.response.BleDataResponse):void");
    }

    public static void settingScheduleSwitch(boolean z, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.SettingScheduleSwitch, new byte[]{z ? (byte) 1 : (byte) 0}, 2, bleDataResponse);
    }

    public static void settingScreenTime(int i2, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(289, new byte[]{(byte) i2}, 2, bleDataResponse);
    }

    public static void settingSkin(int i2, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(277, new byte[]{(byte) i2}, 2, bleDataResponse);
    }

    public static void settingSleepRemind(int i2, int i3, int i4, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(282, new byte[]{(byte) i2, (byte) i3, (byte) i4}, 2, bleDataResponse);
    }

    public static void settingSosSwitch(int i2, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(310, new byte[]{(byte) i2}, 2, bleDataResponse);
    }

    public static void settingSportHeartAlarm(int i2, int i3, int i4, int i5, int i6, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.SettingSportHeartAlarm, new byte[]{(byte) i2, (byte) i3, (byte) i4, (byte) i5, (byte) i6}, 2, bleDataResponse);
    }

    public static void settingStepCountingStateTime(int i2, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.SettingStepCountingStateTime, new byte[]{(byte) i2}, 2, bleDataResponse);
    }

    public static void settingStudentData(String str, String str2, String str3, BleDataResponse bleDataResponse) {
        if (str == null || str2 == null || str3 == null) {
            return;
        }
        try {
            byte[] bytes = str.getBytes("UTF-8");
            byte[] bytes2 = str2.getBytes("UTF-8");
            byte[] bytes3 = str3.getBytes("UTF-8");
            byte[] bArr = new byte[bytes3.length + bytes2.length + bytes.length + 3];
            System.arraycopy(bytes, 0, bArr, 0, bytes.length);
            System.arraycopy(bytes2, 0, bArr, bytes.length + 1, bytes2.length);
            System.arraycopy(bytes3, 0, bArr, bytes.length + bytes2.length + 2, bytes3.length);
            YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.SettingStudentData, bArr, 2, bleDataResponse);
        } catch (Exception e2) {
            e2.printStackTrace();
        }
    }

    public static void settingTemperatureAlarm(boolean z, int i2, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.SettingTemperatureAlarm, new byte[]{z ? (byte) 1 : (byte) 0, (byte) i2, 0}, 2, bleDataResponse);
    }

    public static void settingTemperatureMonitor(boolean z, int i2, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.SettingTemperatureMonitor, new byte[]{z ? (byte) 1 : (byte) 0, (byte) i2}, 2, bleDataResponse);
    }

    public static void settingTime(long j2, BleDataResponse bleDataResponse) {
        if (bleDataResponse == null) {
            bleDataResponse = new BleDataResponse() { // from class: com.yucheng.ycbtsdk.YCBTClient.2
                AnonymousClass2() {
                }

                @Override // com.yucheng.ycbtsdk.response.BleDataResponse
                public void onDataResponse(int i2, float f2, HashMap hashMap) {
                }
            };
        }
        YCBTClientImpl.getInstance().sendSingleData2Device(256, TimeUtil.makeBleTime(j2), 2, bleDataResponse);
    }

    public static void settingTime(BleDataResponse bleDataResponse) {
        if (bleDataResponse == null) {
            bleDataResponse = new BleDataResponse() { // from class: com.yucheng.ycbtsdk.YCBTClient.1
                AnonymousClass1() {
                }

                @Override // com.yucheng.ycbtsdk.response.BleDataResponse
                public void onDataResponse(int i2, float f2, HashMap hashMap) {
                }
            };
        }
        YCBTClientImpl.getInstance().sendSingleData2Device(256, TimeUtil.makeBleTime(), 2, bleDataResponse);
    }

    public static void settingTimeZone(BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.SettingTimeZone, TimeUtil.makeBleTimeZone(), 2, bleDataResponse);
    }

    public static void settingUnit(int i2, int i3, int i4, int i5, int i6, int i7, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(260, new byte[]{(byte) i2, (byte) i3, (byte) i4, (byte) i5, (byte) i6, (byte) i7}, 2, bleDataResponse);
    }

    public static void settingUnit(int i2, int i3, int i4, int i5, int i6, BleDataResponse bleDataResponse) {
        settingUnit(i2, i3, i4, i5, i6, 0, bleDataResponse);
    }

    public static void settingUnit(int i2, int i3, int i4, int i5, BleDataResponse bleDataResponse) {
        settingUnit(i2, i3, i4, i5, 0, bleDataResponse);
    }

    public static void settingUploadReminder(boolean z, int i2, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.SettingUploadReminder, new byte[]{z ? (byte) 1 : (byte) 0, (byte) i2}, 2, bleDataResponse);
    }

    public static void settingUserInfo(int i2, int i3, int i4, int i5, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(259, new byte[]{(byte) i2, (byte) i3, (byte) i4, (byte) i5}, 2, bleDataResponse);
    }

    public static void settingVibrationIntensity(int i2, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(316, new byte[]{(byte) i2}, 2, bleDataResponse);
    }

    public static void settingVibrationTime(int i2, int i3, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(314, new byte[]{(byte) i2, (byte) i3, (byte) ((i3 >> 8) & 255), (byte) ((i3 >> 16) & 255), (byte) ((i3 >> 24) & 255), 0, 0}, 2, bleDataResponse);
    }

    public static void settingWorkingMode(int i2, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.SettingWorkingMode, new byte[]{(byte) i2}, 2, bleDataResponse);
    }

    public static void specificInformationPush(int i2, String str, String str2, BleDataResponse bleDataResponse) {
        if (TextUtils.isEmpty(str) || TextUtils.isEmpty(str2)) {
            bleDataResponse.onDataResponse(-1, -1.0f, null);
            return;
        }
        try {
            YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.SpecificInformationPush, ByteUtil.byteMerger(new byte[]{(byte) i2}, ByteUtil.byteMerger(ByteUtil.getData(str, 32).getBytes("utf-8"), ByteUtil.getData(str2, 512).getBytes("utf-8"))), 2, bleDataResponse);
        } catch (UnsupportedEncodingException e2) {
            e2.printStackTrace();
            bleDataResponse.onDataResponse(-1, -1.0f, null);
        }
    }

    public static void startCollection(int i2, int i3, BleDataResponse bleDataResponse) {
        YCBTLog.e("onOff=" + i2 + " type=" + i3 + " dataResponse" + bleDataResponse);
        byte[] bArr = new byte[19];
        bArr[0] = (byte) i2;
        bArr[1] = (byte) i3;
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.StartCollection, bArr, 2, bleDataResponse);
    }

    public static void startCustomizeDataSync(int i2, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(3445, new byte[]{1, (byte) i2, 1}, 2, bleDataResponse);
    }

    public static void startScanBle(BleScanListResponse bleScanListResponse, int i2) {
        BleHelper.getHelper().setProductId(0);
        if (isScaning()) {
            YCBTLog.e("YCBTClient isScaning 搜索设备中，不能重复调用搜索");
        } else {
            YCBTLog.e("YCBTClient startScanBle");
            YCBTClientImpl.getInstance().startScanBle(bleScanListResponse, i2);
        }
    }

    public static void startScanBle(BleScanListResponse bleScanListResponse, int i2, int i3) {
        BleHelper.getHelper().setProductId(i3);
        if (isScaning()) {
            YCBTLog.e("YCBTClient isScaning 搜索设备中，不能重复调用搜索");
        } else {
            YCBTLog.e("YCBTClient startScanBle");
            YCBTClientImpl.getInstance().startScanBle(bleScanListResponse, i2);
        }
    }

    public static void startScanBle(BleScanListResponse bleScanListResponse, int i2, List<String> list) {
        BleHelper.getHelper().setProductIds(list);
        if (isScaning()) {
            YCBTLog.e("YCBTClient isScaning 搜索设备中，不能重复调用搜索");
        } else {
            YCBTLog.e("YCBTClient startScanBle");
            YCBTClientImpl.getInstance().startScanBle(bleScanListResponse, i2);
        }
    }

    public static void startScanBle(BleScanResponse bleScanResponse, int i2) {
        if (isScaning()) {
            YCBTLog.e("YCBTClient isScaning 搜索设备中，不能重复调用搜索");
        } else {
            YCBTLog.e("YCBTClient startScanBle");
            YCBTClientImpl.getInstance().startScanBle(bleScanResponse, i2);
        }
    }

    public static void startScanBle(BleScanResponse bleScanResponse, int i2, int i3) {
        BleHelper.getHelper().setProductId(i3);
        startScanBle(bleScanResponse, i2);
    }

    public static void startScanBle(BleScanResponse bleScanResponse, int i2, List<String> list) {
        BleHelper.getHelper().setProductIds(list);
        startScanBle(bleScanResponse, i2);
    }

    public static void stopScanBle() {
        if (isScaning()) {
            YCBTLog.e("YCBTClient stopScanBle");
        }
        YCBTClientImpl.getInstance().stopScanBle();
    }

    public static void unRegisterBleStateChange(BleConnectResponse bleConnectResponse) {
        YCBTClientImpl.getInstance().unregisterBleStateChangeCallBack(bleConnectResponse);
    }

    public static void upgradeFirmware(Context context2, String str, String str2, String str3, DfuCallBack dfuCallBack) {
        if (str2 != null && str2.toLowerCase(Locale.ROOT).contains(DfuBaseService.NOTIFICATION_CHANNEL_DFU)) {
            NordicDfuUpdateUtil.getInstance(context2).dfuInit(str, str2, str3, dfuCallBack);
            return;
        }
        if (connectState() == 10) {
            UpgradeFirmwareUtil.startUpgrade(context2, str3, dfuCallBack);
        } else if (!TextUtils.isEmpty(str)) {
            connectBle(str, new BleConnectResponse() { // from class: com.yucheng.ycbtsdk.YCBTClient.12
                final /* synthetic */ DfuCallBack val$callBack;
                final /* synthetic */ Context val$context;
                final /* synthetic */ String val$filePath;

                AnonymousClass12(Context context22, String str32, DfuCallBack dfuCallBack2) {
                    r1 = context22;
                    r2 = str32;
                    r3 = dfuCallBack2;
                }

                @Override // com.yucheng.ycbtsdk.response.BleConnectResponse
                public void onConnectResponse(int i2) {
                    if (i2 == 0) {
                        if (YCBTClient.isOta() || YCBTClient.isForceOta()) {
                            UpgradeFirmwareUtil.startUpgrade(r1, r2, r3);
                        }
                    }
                }
            });
        } else if (dfuCallBack2 != null) {
            dfuCallBack2.error("mac is null");
        }
    }

    public static void vibrationMotor(int i2, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.VibrationMotorControl, new byte[]{1, (byte) i2}, 2, bleDataResponse);
    }

    public static void vibrationMotorControl(int i2, int i3, int i4, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(Constants.DATATYPE.VibrationMotorControl, new byte[]{2, (byte) i2, (byte) ((i2 >> 8) & 255), (byte) i3, (byte) ((i3 >> 8) & 255), (byte) i4, (byte) ((i4 >> 8) & 255)}, 2, bleDataResponse);
    }

    public static void watchDialDelete(int i2, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(2308, new byte[]{(byte) i2, (byte) ((i2 >> 8) & 255), (byte) ((i2 >> 16) & 255), (byte) ((i2 >> 24) & 255)}, 2, bleDataResponse);
    }

    public static void watchDialDownload(int i2, byte[] bArr, int i3, int i4, int i5, BleDataResponse bleDataResponse) {
        if (bArr == null) {
            return;
        }
        int length = bArr.length;
        int crc16_compute = ByteUtil.crc16_compute(bArr, bArr.length);
        YCBTClientImpl.setWatchDialDownloadData(bArr);
        YCBTClientImpl.getInstance().sendSingleData2Device(2304, new byte[]{(byte) i2, (byte) length, (byte) ((length >> 8) & 255), (byte) ((length >> 16) & 255), (byte) ((length >> 24) & 255), (byte) i3, (byte) ((i3 >> 8) & 255), (byte) ((i3 >> 16) & 255), (byte) ((i3 >> 24) & 255), (byte) i4, (byte) ((i4 >> 8) & 255), (byte) i5, (byte) ((i5 >> 8) & 255), (byte) crc16_compute, (byte) ((crc16_compute >> 8) & 255)}, 2, bleDataResponse);
    }

    public static void watchDialInfo(BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(2307, new byte[]{0}, 3, bleDataResponse);
    }

    public static void watchDialSetCurrent(int i2, BleDataResponse bleDataResponse) {
        YCBTClientImpl.getInstance().sendSingleData2Device(2309, new byte[]{(byte) i2, (byte) ((i2 >> 8) & 255), (byte) ((i2 >> 16) & 255), (byte) ((i2 >> 24) & 255)}, 2, bleDataResponse);
    }

    public static void watchUiUpgrade(String str, BleDataResponse bleDataResponse) {
        int i2;
        int i3 = 0;
        if (str == null || "".equals(str)) {
            i2 = 0;
        } else {
            try {
                FileInputStream fileInputStream = new FileInputStream(new File(str));
                byte[] bArr = new byte[1024];
                ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                while (true) {
                    int read = fileInputStream.read(bArr);
                    if (read == -1) {
                        break;
                    } else {
                        byteArrayOutputStream.write(bArr, 0, read);
                    }
                }
                byteArrayOutputStream.flush();
                byte[] byteArray = byteArrayOutputStream.toByteArray();
                int length = byteArray.length;
                i2 = ByteUtil.crc16_compute(byteArray, byteArray.length);
                if (length < 1024) {
                    System.out.println("chong-----传入的文件不是UI升级文件");
                    bleDataResponse.onDataResponse(1, 1.0f, null);
                    return;
                } else {
                    YCBTClientImpl.setWatchDialDownloadData(byteArray);
                    i3 = length;
                }
            } catch (Exception e2) {
                e2.printStackTrace();
                System.out.println("chong-----开始安装UI报错");
                bleDataResponse.onDataResponse(1, 1.0f, null);
                return;
            }
        }
        otaUIGetBreakInfo(new BleDataResponse() { // from class: com.yucheng.ycbtsdk.YCBTClient.7
            final /* synthetic */ int val$crc;
            final /* synthetic */ BleDataResponse val$dataResponse;
            final /* synthetic */ int val$lenth;

            /* renamed from: com.yucheng.ycbtsdk.YCBTClient$7$1 */
            class AnonymousClass1 implements BleDataResponse {
                final /* synthetic */ int val$finalUiFileOffset;

                AnonymousClass1(int intValue22) {
                    r2 = intValue22;
                }

                @Override // com.yucheng.ycbtsdk.response.BleDataResponse
                public void onDataResponse(int i2, float f2, HashMap hashMap) {
                    /*
                        this = this;
                        if (r7 != 0) goto L11
                        if (r9 == 0) goto L11
                        java.lang.String r7 = "chipScheme"
                        java.lang.Object r7 = r9.get(r7)
                        java.lang.Integer r7 = (java.lang.Integer) r7
                        int r7 = r7.intValue()
                        goto L12
                    L11:
                        r7 = 0
                    L12:
                        if (r7 != 0) goto L1f
                        com.yucheng.ycbtsdk.YCBTClient$7 r7 = com.yucheng.ycbtsdk.YCBTClient.AnonymousClass7.this
                        int r7 = r1
                        int r8 = r7 % 1024
                        int r7 = r7 / 1024
                        if (r8 != 0) goto L2a
                        goto L2c
                    L1f:
                        com.yucheng.ycbtsdk.YCBTClient$7 r7 = com.yucheng.ycbtsdk.YCBTClient.AnonymousClass7.this
                        int r7 = r1
                        int r8 = r7 % 4096
                        int r7 = r7 / 4096
                        if (r8 != 0) goto L2a
                        goto L2c
                    L2a:
                        int r7 = r7 + 1
                    L2c:
                        r2 = r7
                        com.yucheng.ycbtsdk.YCBTClient$7 r7 = com.yucheng.ycbtsdk.YCBTClient.AnonymousClass7.this
                        int r0 = r1
                        int r3 = r2
                        int r1 = r0 - r3
                        int r4 = r2
                        com.yucheng.ycbtsdk.response.BleDataResponse r5 = r3
                        com.yucheng.ycbtsdk.YCBTClient.otaUIFileInfo(r0, r1, r2, r3, r4, r5)
                        return
                    */
                    throw new UnsupportedOperationException("Method not decompiled: com.yucheng.ycbtsdk.YCBTClient.AnonymousClass7.AnonymousClass1.onDataResponse(int, float, java.util.HashMap):void");
                }
            }

            AnonymousClass7(int i32, int i22, BleDataResponse bleDataResponse2) {
                r1 = i32;
                r2 = i22;
                r3 = bleDataResponse2;
            }

            @Override // com.yucheng.ycbtsdk.response.BleDataResponse
            public void onDataResponse(int i22, float f2, HashMap hashMap) {
                if (i22 != 0 || hashMap == null) {
                    r3.onDataResponse(1, 1.0f, null);
                    return;
                }
                int intValue = ((Integer) hashMap.get("uiFileTotalLen")).intValue();
                int intValue22 = ((Integer) hashMap.get("uiFileOffset")).intValue();
                int intValue3 = ((Integer) hashMap.get("uiFileCheckSum")).intValue();
                if (intValue == 0 || intValue != r1 || intValue3 != r2) {
                    intValue22 = 0;
                }
                YCBTClient.getChipScheme(new BleDataResponse() { // from class: com.yucheng.ycbtsdk.YCBTClient.7.1
                    final /* synthetic */ int val$finalUiFileOffset;

                    AnonymousClass1(int intValue222) {
                        r2 = intValue222;
                    }

                    @Override // com.yucheng.ycbtsdk.response.BleDataResponse
                    public void onDataResponse(int i4, float f3, HashMap hashMap2) {
                        /*
                            this = this;
                            if (r7 != 0) goto L11
                            if (r9 == 0) goto L11
                            java.lang.String r7 = "chipScheme"
                            java.lang.Object r7 = r9.get(r7)
                            java.lang.Integer r7 = (java.lang.Integer) r7
                            int r7 = r7.intValue()
                            goto L12
                        L11:
                            r7 = 0
                        L12:
                            if (r7 != 0) goto L1f
                            com.yucheng.ycbtsdk.YCBTClient$7 r7 = com.yucheng.ycbtsdk.YCBTClient.AnonymousClass7.this
                            int r7 = r1
                            int r8 = r7 % 1024
                            int r7 = r7 / 1024
                            if (r8 != 0) goto L2a
                            goto L2c
                        L1f:
                            com.yucheng.ycbtsdk.YCBTClient$7 r7 = com.yucheng.ycbtsdk.YCBTClient.AnonymousClass7.this
                            int r7 = r1
                            int r8 = r7 % 4096
                            int r7 = r7 / 4096
                            if (r8 != 0) goto L2a
                            goto L2c
                        L2a:
                            int r7 = r7 + 1
                        L2c:
                            r2 = r7
                            com.yucheng.ycbtsdk.YCBTClient$7 r7 = com.yucheng.ycbtsdk.YCBTClient.AnonymousClass7.this
                            int r0 = r1
                            int r3 = r2
                            int r1 = r0 - r3
                            int r4 = r2
                            com.yucheng.ycbtsdk.response.BleDataResponse r5 = r3
                            com.yucheng.ycbtsdk.YCBTClient.otaUIFileInfo(r0, r1, r2, r3, r4, r5)
                            return
                        */
                        throw new UnsupportedOperationException("Method not decompiled: com.yucheng.ycbtsdk.YCBTClient.AnonymousClass7.AnonymousClass1.onDataResponse(int, float, java.util.HashMap):void");
                    }
                });
            }
        });
    }
}
