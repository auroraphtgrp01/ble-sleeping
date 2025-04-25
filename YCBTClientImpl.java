package com.yucheng.ycbtsdk.core;

import android.bluetooth.BluetoothGatt;
import android.content.Context;
import android.os.Handler;
import com.alibaba.fastjson2.JSONB;
import com.facebook.internal.ServerProtocol;
import com.google.firebase.crashlytics.buildtools.reloc.org.apache.commons.cli.HelpFormatter;
import com.yucheng.ycbtsdk.Constants;
import com.yucheng.ycbtsdk.YCBTClient;
import com.yucheng.ycbtsdk.bean.ScanDeviceBean;
import com.yucheng.ycbtsdk.gatt.BleHelper;
import com.yucheng.ycbtsdk.gatt.GattBleResponse;
import com.yucheng.ycbtsdk.gatt.Reconnect;
import com.yucheng.ycbtsdk.jl.JLOTAManager;
import com.yucheng.ycbtsdk.jl.WatchManager;
import com.yucheng.ycbtsdk.response.BleConnectResponse;
import com.yucheng.ycbtsdk.response.BleDataResponse;
import com.yucheng.ycbtsdk.response.BleDeviceToAppDataResponse;
import com.yucheng.ycbtsdk.response.BleRealDataResponse;
import com.yucheng.ycbtsdk.response.BleScanListResponse;
import com.yucheng.ycbtsdk.response.BleScanResponse;
import com.yucheng.ycbtsdk.utils.ByteUtil;
import com.yucheng.ycbtsdk.utils.LogToFileUtils;
import com.yucheng.ycbtsdk.utils.SPUtil;
import com.yucheng.ycbtsdk.utils.TimeUtil;
import com.yucheng.ycbtsdk.utils.YCBTLog;
import com.zhihu.matisse.internal.loader.AlbumLoader;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/* loaded from: classes4.dex */
public class YCBTClientImpl implements GattBleResponse {
    private static byte[] otaDownloadData;
    private static volatile YCBTClientImpl sInstance;
    private static byte[] watchDialDownloadData;
    private Context context;
    private byte[] datas;
    private boolean isRecvRealEcging;
    private BleConnectResponse mBleConnectResponse;
    private BleDeviceToAppDataResponse mBleDeviceToAppResponse;
    private BleRealDataResponse mBleRealDataResponse;
    private BleScanListResponse mBleScanListResponse;
    private BleScanResponse mBleScanResponse;
    private ArrayList<BleConnectResponse> mBleStatelistens;
    private ArrayList mBlockArray;
    private BleRealDataResponse mECGBleRealDataResponse;
    private int mEndTimeOutCount;
    private ArrayList mLastBlockArray;
    private boolean mQueueSendState;
    private CopyOnWriteArrayList<YCSendBean> mSendQueue;
    private Handler mTimeOutHander;
    private BleDataResponse sendingDataResponse;
    private int mBleStateCode = 3;
    private boolean isGattWriteCallBackFinish = true;
    private int mBlockFrame = 0;
    private HashMap scheduleInfo = new HashMap();
    private List<HashMap> scheduleInfos = new ArrayList();
    private boolean isWatchDialPause = false;
    private boolean isRealData = false;
    public boolean isOta = false;
    public boolean isForceOta = false;
    public long totalSendLength = 0;
    public int lastCrc = -1;
    public int lastPacketIndex = -1;
    public int crcFailCount = 0;
    public boolean isStartThree = false;
    public boolean isTool = false;
    private Runnable mTimerOutRunnable = new Runnable() { // from class: com.yucheng.ycbtsdk.core.YCBTClientImpl.1
        @Override // java.lang.Runnable
        public void run() {
            YCBTLog.e("TimeOut");
            YCBTClientImpl.this.stopScanBle();
        }
    };
    private Runnable mTimeRunnable = new Runnable() { // from class: com.yucheng.ycbtsdk.core.YCBTClientImpl.2
        /* JADX WARN: Code restructure failed: missing block: B:44:0x0119, code lost:
        
            if (r7.this$0.mSendQueue.size() > 0) goto L42;
         */
        /* JADX WARN: Code restructure failed: missing block: B:8:0x0064, code lost:
        
            if (r7.this$0.mSendQueue.size() > 0) goto L42;
         */
        /* JADX WARN: Code restructure failed: missing block: B:9:0x011b, code lost:
        
            ((com.yucheng.ycbtsdk.core.YCSendBean) r7.this$0.mSendQueue.get(0)).collectStopReset();
         */
        @Override // java.lang.Runnable
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct code enable 'Show inconsistent code' option in preferences
        */
        public void run() {
            /*
                Method dump skipped, instructions count: 304
                To view this dump change 'Code comments level' option to 'DEBUG'
            */
            throw new UnsupportedOperationException("Method not decompiled: com.yucheng.ycbtsdk.core.YCBTClientImpl.AnonymousClass2.run():void");
        }
    };
    private int mEndEcgTimeOutCount = 0;
    private Runnable mEndEcgTestOut = new Runnable() { // from class: com.yucheng.ycbtsdk.core.YCBTClientImpl.3
        @Override // java.lang.Runnable
        public void run() {
            YCBTClientImpl.access$704(YCBTClientImpl.this);
            YCBTLog.e("实时ECG结束超时,重发 " + YCBTClientImpl.this.mEndEcgTimeOutCount);
            if (YCBTClientImpl.this.mEndEcgTimeOutCount > 3) {
                YCBTClientImpl.this.isRecvRealEcging = false;
                YCBTClientImpl.this.mTimeOutHander.removeCallbacks(YCBTClientImpl.this.mEndEcgTestOut);
                if (YCBTClientImpl.this.sendingDataResponse != null) {
                    YCBTClientImpl.this.sendingDataResponse.onDataResponse(1, 0.0f, null);
                }
                YCBTClientImpl.this.mEndEcgTimeOutCount = 0;
                YCBTClientImpl.this.popQueue();
                return;
            }
            if (YCBTClientImpl.this.mSendQueue.size() == 0) {
                return;
            }
            ((YCSendBean) YCBTClientImpl.this.mSendQueue.get(0)).resetGroup(Constants.DATATYPE.AppBloodSwitch, new byte[]{0});
            YCBTClientImpl.this.frontQueue();
            YCBTClientImpl.this.mTimeOutHander.removeCallbacks(YCBTClientImpl.this.mEndEcgTestOut);
            YCBTClientImpl.this.mTimeOutHander.postDelayed(YCBTClientImpl.this.mEndEcgTestOut, 2500L);
        }
    };
    private int bondingCount = 0;
    private Runnable bondingRunnable = new Runnable() { // from class: com.yucheng.ycbtsdk.core.YCBTClientImpl.5
        @Override // java.lang.Runnable
        public void run() {
            YCBTClientImpl.this.frontQueue();
            if (YCBTClientImpl.this.bondingCount < 12) {
                YCBTClientImpl.access$1108(YCBTClientImpl.this);
            } else {
                YCBTClientImpl.this.bondingCount = 0;
                YCBTClientImpl.this.isBonding = false;
            }
        }
    };
    public boolean isBonding = false;
    private int fileSize = 0;
    private int dialLength = 0;
    private int dialSize = 4096;
    private int currentDataIndex = 0;
    private int remainderPackage = 0;
    private int oldDataIndex = 0;
    private int otaIndex = 0;
    private int otaLength = 0;`
    private int otaSize = 4096;
    private int currentOtaIndex = 0;
    private int remainderOtaPackage = 0;
    private int oldOtaIndex = 0;
    private int dialIndex = 0;
    private boolean isFlag = false;

    static /* synthetic */ int access$104(YCBTClientImpl yCBTClientImpl) {
        int i2 = yCBTClientImpl.mEndTimeOutCount + 1;
        yCBTClientImpl.mEndTimeOutCount = i2;
        return i2;
    }

    static /* synthetic */ int access$1108(YCBTClientImpl yCBTClientImpl) {
        int i2 = yCBTClientImpl.bondingCount;
        yCBTClientImpl.bondingCount = i2 + 1;
        return i2;
    }

    static /* synthetic */ int access$704(YCBTClientImpl yCBTClientImpl) {
        int i2 = yCBTClientImpl.mEndEcgTimeOutCount + 1;
        yCBTClientImpl.mEndEcgTimeOutCount = i2;
        return i2;
    }

    private void dataResponse(int i2, float f2, HashMap hashMap) {
        try {
            YCBTLog.e("dataResponse code=" + i2 + " " + this.sendingDataResponse);
            BleDataResponse bleDataResponse = this.sendingDataResponse;
            if (bleDataResponse != null) {
                bleDataResponse.onDataResponse(i2, 0.0f, hashMap);
            }
        } catch (Exception e2) {
            e2.printStackTrace();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void frontQueue() {
        String str;
        int i2;
        int i3;
        synchronized (this) {
            YCBTLog.e("frontQueue " + this.isGattWriteCallBackFinish);
            if (this.mSendQueue.size() > 0) {
                if (isBonding()) {
                    this.mTimeOutHander.removeCallbacks(this.bondingRunnable);
                    this.mTimeOutHander.postDelayed(this.bondingRunnable, 1000L);
                    return;
                }
                this.bondingCount = 0;
                try {
                    YCSendBean yCSendBean = this.mSendQueue.get(0);
                    this.sendingDataResponse = yCSendBean.mDataResponse;
                    if (this.isGattWriteCallBackFinish) {
                        byte[] willSendFrame = yCSendBean.willSendFrame();
                        if (willSendFrame != null && ((i2 = this.mBleStateCode) == 10 || ((i2 == 9 && ((i3 = yCSendBean.dataType) == 256 || i3 == 513 || i3 == 539 || i3 == 512 || i3 == 43690)) || (this.isForceOta && yCSendBean.dataType == 43690)))) {
                            this.mQueueSendState = true;
                            int i4 = yCSendBean.dataType;
                            if (i4 != 43690 && i4 != 48059 && i4 != 52428) {
                                int i5 = yCSendBean.groupType;
                                if (i5 == 1 || i5 == 8 || i5 == 9 || i5 == 12) {
                                    this.mTimeOutHander.removeCallbacks(this.mTimeRunnable);
                                    this.mTimeOutHander.postDelayed(this.mTimeRunnable, 3000L);
                                }
                                if (yCSendBean.groupType == 3) {
                                    this.mTimeOutHander.removeCallbacks(this.mTimeRunnable);
                                    this.mTimeOutHander.postDelayed(this.mTimeRunnable, 30000L);
                                }
                                sendData2Device(yCSendBean.dataType, willSendFrame);
                            }
                            BleHelper.getHelper().jlGattWriteData(yCSendBean.willData);
                        } else if (willSendFrame != null) {
                            YCBTLog.e("tWillSendFrame != null");
                            popQueue();
                        } else {
                            str = "tWillSendFrame == null";
                        }
                    } else {
                        str = "frontQueue isGattWriteCallBackFinish == " + this.isGattWriteCallBackFinish;
                    }
                    YCBTLog.e(str);
                } catch (Exception e2) {
                    e2.printStackTrace();
                }
            }
        }
    }

    public static YCBTClientImpl getInstance() {
        if (sInstance == null) {
            synchronized (YCBTClientImpl.class) {
                if (sInstance == null) {
                    sInstance = new YCBTClientImpl();
                }
            }
        }
        return sInstance;
    }

    private byte[] getLastBlockArray(int i2) {
        int i3 = 0;
        for (int i4 = 0; i4 < this.mLastBlockArray.size(); i4++) {
            try {
                i3 += ((byte[]) this.mLastBlockArray.get(i4)).length;
            } catch (Exception e2) {
                e2.printStackTrace();
                return null;
            }
        }
        byte[] bArr = new byte[i3];
        int i5 = 0;
        for (int i6 = 0; i6 < this.mLastBlockArray.size(); i6++) {
            byte[] bArr2 = (byte[]) this.mLastBlockArray.get(i6);
            System.arraycopy(bArr2, 0, bArr, i5, bArr2.length);
            i5 += bArr2.length;
        }
        return bArr;
    }

    private boolean isBonding() {
        return this.isBonding && YCBTClient.connectState() == 10 && ((Integer) SPUtil.get(Constants.FunctionConstant.ISHASCREATEBOND, 0)).intValue() == 1 && BleHelper.getHelper().mBluetoothGatt.getDevice() != null && BleHelper.getHelper().mBluetoothGatt != null && BleHelper.getHelper().mBluetoothGatt.getDevice().getBondState() != 12 && BleHelper.getHelper().mBluetoothGatt.getDevice().getBondState() == 11;
    }

    private boolean isError(byte[] bArr) {
        String str;
        if (bArr != null && bArr.length == 1) {
            byte b2 = bArr[0];
            if ((b2 & JSONB.Constants.BC_INT32_NUM_MIN) == 240) {
                int i2 = b2 & 255;
                if (i2 == 251) {
                    str = "不支持的Command ID";
                } else if (i2 == 252) {
                    str = "不支持的Key";
                } else if (i2 == 253) {
                    str = "Length错误";
                } else if (i2 == 254) {
                    str = "Data错误";
                } else if (i2 == 255) {
                    str = "CRC16校验错误";
                }
                YCBTLog.e(str);
                return true;
            }
        }
        return false;
    }

    private boolean isNeedStopCollect() {
        boolean z = true;
        int i2 = 1;
        while (true) {
            if (i2 >= this.mSendQueue.size()) {
                z = false;
                break;
            }
            if (this.mSendQueue.get(i2).sendPriority > 1) {
                break;
            }
            i2++;
        }
        YCBTLog.e("是否需要停止当前 " + z);
        return z;
    }

    private void next() {
        if (this.isWatchDialPause) {
            pauseDial();
            return;
        }
        int i2 = this.remainderPackage;
        if (i2 <= 0) {
            if (this.mSendQueue.get(0).dataType == 2304) {
                stopDial();
                return;
            }
            return;
        }
        int i3 = BleHelper.MTU - 9;
        int i4 = this.dialSize;
        if (i2 == 1) {
            i4 = this.dialLength - this.oldDataIndex;
        }
        int i5 = i4 / i3;
        int i6 = i4 % i3;
        int i7 = i5 + (i6 == 0 ? 0 : 1);
        int i8 = this.dialIndex;
        if (i8 >= i7) {
            this.dialIndex = 0;
            int i9 = this.currentDataIndex;
            int i10 = this.oldDataIndex;
            int i11 = i9 - i10;
            byte[] bArr = new byte[i11];
            System.arraycopy(watchDialDownloadData, i10, bArr, 0, i11);
            int crc16_compute = ByteUtil.crc16_compute(bArr, i11);
            int i12 = i7 >> 8;
            byte[] bArr2 = {(byte) i11, (byte) (i11 >> 8), (byte) (i11 >> 16), (byte) (i11 >> 24), (byte) i7, (byte) i12, (byte) crc16_compute, (byte) (crc16_compute >> 8)};
            YCBTLog.e("YCBTClientImpl next()----" + i11 + HelpFormatter.DEFAULT_LONG_OPT_PREFIX + i7 + HelpFormatter.DEFAULT_LONG_OPT_PREFIX + crc16_compute + HelpFormatter.DEFAULT_LONG_OPT_PREFIX + i12);
            if (this.isWatchDialPause) {
                return;
            }
            sendData2Device(this.mSendQueue.get(0).dataType == 2304 ? 2306 : 32259, bArr2);
            this.oldDataIndex = this.currentDataIndex;
            this.remainderPackage--;
            return;
        }
        if (i8 == i7 - 1) {
            i3 = i6;
        }
        byte[] bArr3 = new byte[i3];
        System.arraycopy(watchDialDownloadData, this.currentDataIndex, bArr3, 0, i3);
        this.currentDataIndex += i3;
        if (this.isWatchDialPause) {
            return;
        }
        sendData2Device(this.mSendQueue.get(0).dataType == 2304 ? 2305 : 32258, bArr3);
        this.dialIndex++;
        if (this.sendingDataResponse != null) {
            HashMap hashMap = new HashMap();
            hashMap.put("code", 0);
            hashMap.put("progress", Float.valueOf((this.currentDataIndex * 100.0f) / this.dialLength));
            hashMap.put("dataType", Integer.valueOf(Constants.DATATYPE.WatchDialProgress));
            this.sendingDataResponse.onDataResponse(0, 0.0f, hashMap);
        }
    }

    private void nextOta() {
        int i2 = this.remainderOtaPackage;
        if (i2 > 0) {
            int i3 = BleHelper.MTU - 9;
            int i4 = this.otaSize;
            if (i2 == 1) {
                i4 = this.otaLength - this.oldOtaIndex;
            }
            int i5 = i4 / i3;
            int i6 = i4 % i3;
            int i7 = i5 + (i6 == 0 ? 0 : 1);
            int i8 = this.otaIndex;
            if (i8 < i7) {
                if (i8 == i7 - 1) {
                    i3 = i6;
                }
                byte[] bArr = new byte[i3];
                System.arraycopy(otaDownloadData, this.currentOtaIndex, bArr, 0, i3);
                this.currentOtaIndex += i3;
                sendData2Device(Constants.DATATYPE.OtaSend, bArr);
                this.otaIndex++;
                if (this.sendingDataResponse != null) {
                    HashMap hashMap = new HashMap();
                    hashMap.put("code", 0);
                    hashMap.put("progress", Float.valueOf((this.currentOtaIndex * 100.0f) / this.otaLength));
                    hashMap.put("dataType", Integer.valueOf(Constants.DATATYPE.OTAProgress));
                    this.sendingDataResponse.onDataResponse(0, 0.0f, hashMap);
                    return;
                }
                return;
            }
            this.otaIndex = 0;
            int i9 = this.currentOtaIndex;
            int i10 = this.oldOtaIndex;
            int i11 = i9 - i10;
            byte[] bArr2 = new byte[i11];
            System.arraycopy(otaDownloadData, i10, bArr2, 0, i11);
            int crc16_compute = ByteUtil.crc16_compute(bArr2, i11);
            int i12 = i7 >> 8;
            byte[] bArr3 = {(byte) i11, (byte) (i11 >> 8), (byte) (i11 >> 16), (byte) (i11 >> 24), (byte) i7, (byte) i12, (byte) crc16_compute, (byte) (crc16_compute >> 8)};
            YCBTLog.e("YCBTClientImpl next()----" + i11 + HelpFormatter.DEFAULT_LONG_OPT_PREFIX + i7 + HelpFormatter.DEFAULT_LONG_OPT_PREFIX + crc16_compute + HelpFormatter.DEFAULT_LONG_OPT_PREFIX + i12);
            if (this.mSendQueue.get(0).dataType == 2560) {
                sendData2Device(Constants.DATATYPE.OtaBlock, bArr3);
            }
            this.oldOtaIndex = this.currentOtaIndex;
            this.remainderOtaPackage--;
        }
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Code restructure failed: missing block: B:105:0x0133, code lost:
    
        if (r0 != null) goto L87;
     */
    /* JADX WARN: Code restructure failed: missing block: B:130:0x01c1, code lost:
    
        if (r0 != null) goto L87;
     */
    /* JADX WARN: Code restructure failed: missing block: B:135:0x01eb, code lost:
    
        if (r0 != null) goto L87;
     */
    /* JADX WARN: Code restructure failed: missing block: B:144:0x023d, code lost:
    
        if (r0 != null) goto L87;
     */
    /* JADX WARN: Code restructure failed: missing block: B:98:0x0107, code lost:
    
        if (r0 != null) goto L87;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    private void packetAppControlHandle(int r17, int r18, byte[] r19, int r20) {
        /*
            Method dump skipped, instructions count: 789
            To view this dump change 'Code comments level' option to 'DEBUG'
        */
        throw new UnsupportedOperationException("Method not decompiled: com.yucheng.ycbtsdk.core.YCBTClientImpl.packetAppControlHandle(int, int, byte[], int):void");
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:134:0x0516  */
    /* JADX WARN: Removed duplicated region for block: B:82:0x0411  */
    /* JADX WARN: Removed duplicated region for block: B:89:0x041b  */
    /* JADX WARN: Type inference failed for: r4v24, types: [long] */
    /* JADX WARN: Type inference failed for: r4v56, types: [java.lang.String] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    private void packetCollectHandle(int r26, int r27, byte[] r28, int r29) {
        /*
            Method dump skipped, instructions count: 2104
            To view this dump change 'Code comments level' option to 'DEBUG'
        */
        throw new UnsupportedOperationException("Method not decompiled: com.yucheng.ycbtsdk.core.YCBTClientImpl.packetCollectHandle(int, int, byte[], int):void");
    }

    private void packetCollectionToolsHandle(int i2, int i3, byte[] bArr, int i4) {
        HashMap hashMap = null;
        try {
            if (i2 == 1 || i2 == 2) {
                BleDataResponse bleDataResponse = this.sendingDataResponse;
                if (bleDataResponse != null) {
                    bleDataResponse.onDataResponse((bArr == null || bArr.length <= 0) ? -1 : bArr[bArr.length - 1] & 255, 0.0f, null);
                }
            } else {
                byte b2 = 0;
                if (i2 == 3) {
                    if (this.mBleRealDataResponse != null) {
                        try {
                            byte[] bArr2 = new byte[5];
                            System.arraycopy(bArr, 0, bArr2, 0, 4);
                            bArr2[4] = 0;
                            sendData2Device(Constants.DATATYPE.CollectionUpload, bArr2);
                            int i5 = i3 - 4;
                            byte[] bArr3 = new byte[i5];
                            System.arraycopy(bArr, 4, bArr3, 0, i5);
                            HashMap hashMap2 = new HashMap();
                            hashMap2.put("dataBytes", bArr3);
                            hashMap2.put("num", Long.valueOf((bArr[0] & 255) + ((bArr[1] & 255) << 8) + ((bArr[2] & 255) << 16) + ((bArr[3] & 255) << 24)));
                            this.mBleRealDataResponse.onRealDataResponse(Constants.DATATYPE.CollectionUpload, hashMap2);
                            return;
                        } catch (Exception e2) {
                            e2.printStackTrace();
                            return;
                        }
                    }
                    return;
                }
                if (bArr != null) {
                    byte b3 = bArr.length > 0 ? bArr[0] : (byte) 0;
                    if (bArr.length > 1) {
                        hashMap = new HashMap();
                        hashMap.put("data", Byte.valueOf(bArr[1]));
                        CopyOnWriteArrayList<YCSendBean> copyOnWriteArrayList = this.mSendQueue;
                        if (copyOnWriteArrayList != null && copyOnWriteArrayList.size() > 0) {
                            hashMap.put("dataType", Integer.valueOf(this.mSendQueue.get(0).dataType));
                        }
                    }
                    b2 = b3;
                }
                BleDataResponse bleDataResponse2 = this.sendingDataResponse;
                if (bleDataResponse2 != null) {
                    bleDataResponse2.onDataResponse(b2, 0.0f, hashMap);
                }
            }
        } catch (Exception e3) {
            e3.printStackTrace();
        }
        popQueue();
    }

    private void packetCustomizeHandle(int i2, int i3, byte[] bArr, int i4) {
        if (i2 == 1) {
            try {
                try {
                    HashMap<String, Object> unpackCustomizeCGM = DataUnpack.unpackCustomizeCGM(bArr);
                    dataResponse(((Integer) unpackCustomizeCGM.get("code")).intValue(), 0.0f, unpackCustomizeCGM);
                } catch (Exception e2) {
                    e2.printStackTrace();
                }
            } finally {
            }
        } else {
            if (i2 != 2) {
                if (i2 != 117) {
                    return;
                }
                try {
                    HashMap<String, Object> unpackCustomizeData = DataUnpack.unpackCustomizeData(bArr);
                    int intValue = ((Integer) unpackCustomizeData.get("code")).intValue();
                    int intValue2 = ((Integer) unpackCustomizeData.get("opcode")).intValue();
                    unpackCustomizeData.remove("opcode");
                    if (intValue2 == 1) {
                        int intValue3 = ((Integer) unpackCustomizeData.get(AlbumLoader.COLUMN_COUNT)).intValue();
                        int intValue4 = ((Integer) unpackCustomizeData.get(ServerProtocol.DIALOG_PARAM_STATE)).intValue();
                        ((Integer) unpackCustomizeData.get("packageNum")).intValue();
                        ((Integer) unpackCustomizeData.get("total")).intValue();
                        unpackCustomizeData.remove(AlbumLoader.COLUMN_COUNT);
                        unpackCustomizeData.remove(ServerProtocol.DIALOG_PARAM_STATE);
                        unpackCustomizeData.remove("packageNum");
                        unpackCustomizeData.remove("total");
                        if (intValue4 != 1 && intValue4 != 2) {
                            if (intValue3 != 0) {
                                return;
                            }
                        }
                        unpackCustomizeData.put("code", 1);
                    } else if (intValue2 != 3) {
                        if (intValue2 == 2) {
                            BleRealDataResponse bleRealDataResponse = this.mBleRealDataResponse;
                            if (bleRealDataResponse != null) {
                                bleRealDataResponse.onRealDataResponse(3445, unpackCustomizeData);
                                return;
                            }
                            return;
                        }
                        if (intValue2 == 128) {
                            try {
                                if (intValue == 0) {
                                    ByteBuffer allocate = ByteBuffer.allocate(3);
                                    int intValue5 = ((Integer) unpackCustomizeData.get("type")).intValue();
                                    allocate.put((byte) intValue2);
                                    allocate.put((byte) intValue5);
                                    allocate.put((byte) 0);
                                    sendData2Device(3445, allocate.array());
                                } else {
                                    sendData2Device(3445, new byte[]{4});
                                }
                                dataResponse(intValue, 0.0f, unpackCustomizeData);
                                return;
                            } catch (Exception e3) {
                                resetQueue();
                                e3.printStackTrace();
                                return;
                            }
                        }
                    }
                    dataResponse(intValue, 0.0f, unpackCustomizeData);
                    return;
                } catch (Exception e4) {
                    resetQueue();
                    e4.printStackTrace();
                    return;
                }
            }
            try {
                try {
                    HashMap<String, Object> unpackWit = DataUnpack.unpackWit(bArr);
                    dataResponse(((Integer) unpackWit.get("code")).intValue(), 0.0f, unpackWit);
                } finally {
                }
            } catch (Exception e5) {
                e5.printStackTrace();
            }
        }
    }

    private void packetDevControlHandle(int i2, int i3, byte[] bArr, int i4) {
        int i5;
        switch (i2) {
            case 0:
                i5 = 1024;
                break;
            case 1:
                i5 = 1025;
                break;
            case 2:
                i5 = 1026;
                break;
            case 3:
                i5 = 1027;
                break;
            case 4:
                i5 = 1028;
                break;
            case 5:
                i5 = 1029;
                break;
            case 6:
                i5 = 1030;
                break;
            case 7:
                i5 = Constants.DATATYPE.DeviceConnectOrDisconnect;
                break;
            case 8:
                i5 = Constants.DATATYPE.DeviceSportMode;
                break;
            case 9:
                i5 = Constants.DATATYPE.DeviceSyncContacts;
                break;
            case 10:
                i5 = Constants.DATATYPE.DeviceRest;
                break;
            case 11:
                this.isRecvRealEcging = false;
                i5 = Constants.DATATYPE.DeviceEndECG;
                break;
            case 12:
                i5 = Constants.DATATYPE.DeviceSportModeControl;
                break;
            case 13:
                i5 = Constants.DATATYPE.DeviceSwitchDial;
                break;
            case 14:
                i5 = Constants.DATATYPE.DeviceMeasurementResult;
                break;
            case 15:
                i5 = Constants.DATATYPE.DeviceAlarmData;
                break;
            case 16:
                i5 = 1040;
                break;
            case 17:
                i5 = Constants.DATATYPE.DeviceUpgradeResult;
                break;
            case 18:
                i5 = Constants.DATATYPE.DevicePPIData;
                break;
            case 19:
                i5 = Constants.DATATYPE.DeviceMeasurStatusAndResults;
                break;
            case 20:
            default:
                i5 = -1;
                break;
            case 21:
                i5 = Constants.DATATYPE.DeviceRequestDynamicCode;
                break;
            case 22:
                i5 = Constants.DATATYPE.DeviceSedentaryReminder;
                break;
            case 23:
                i5 = Constants.DATATYPE.DeviceReportAlarm;
                break;
        }
        if (i5 != -1) {
            if (this.mBleDeviceToAppResponse != null) {
                try {
                    sendData2Device(i5, new byte[]{0});
                    this.mBleDeviceToAppResponse.onDataResponse(0, DataUnpack.unpackParseData(bArr, i5));
                } catch (Exception e2) {
                    e2.printStackTrace();
                    sendData2Device(i5, new byte[]{1});
                    this.mBleDeviceToAppResponse.onDataResponse(1, null);
                }
            }
            popQueue();
        }
    }

    private void packetDialHandle(int i2, int i3, byte[] bArr, int i4) {
        HashMap hashMap;
        BleDataResponse bleDataResponse;
        byte b2;
        int i5;
        if (i2 != 0) {
            if (i2 == 2) {
                if (bArr.length >= 1 && bArr[0] == 0) {
                    next();
                    return;
                }
                HashMap hashMap2 = new HashMap();
                hashMap2.put("code", 0);
                hashMap2.put("data", bArr);
                hashMap2.put("dataType", 2304);
                BleDataResponse bleDataResponse2 = this.sendingDataResponse;
                if (bleDataResponse2 != null) {
                    bleDataResponse2.onDataResponse(1, 0.0f, hashMap2);
                    return;
                }
                return;
            }
            if (i2 == 3) {
                hashMap = DataUnpack.unpackDialInfo(bArr);
                bleDataResponse = this.sendingDataResponse;
                if (bleDataResponse != null) {
                    if (hashMap != null) {
                        r4 = 0;
                    }
                    bleDataResponse.onDataResponse(r4, 0.0f, hashMap);
                }
            } else if (i2 == 4) {
                hashMap = new HashMap();
                hashMap.put("code", 0);
                hashMap.put("data", bArr);
                hashMap.put("dataType", 2308);
                bleDataResponse = this.sendingDataResponse;
                if (bleDataResponse != null) {
                    b2 = bArr[0];
                    bleDataResponse.onDataResponse(b2, 0.0f, hashMap);
                }
            } else {
                if (i2 != 5) {
                    return;
                }
                hashMap = new HashMap();
                hashMap.put("code", 0);
                hashMap.put("data", bArr);
                hashMap.put("dataType", 2309);
                bleDataResponse = this.sendingDataResponse;
                if (bleDataResponse != null) {
                    b2 = bArr[0];
                    bleDataResponse.onDataResponse(b2, 0.0f, hashMap);
                }
            }
        } else {
            if (bArr.length >= 2 && bArr[0] == 1 && bArr[1] == 0) {
                byte[] bArr2 = this.mSendQueue.get(0).willData;
                if (bArr2 == null || bArr2.length <= 9 || (i5 = (bArr2[9] & 255) + ((bArr2[10] & 255) << 8)) == 255) {
                    i5 = 0;
                }
                this.dialIndex = 0;
                int i6 = this.dialSize;
                int i7 = i5 * i6;
                this.currentDataIndex = i7;
                this.oldDataIndex = i7;
                int length = watchDialDownloadData.length;
                this.dialLength = length;
                this.remainderPackage = ((length / i6) + (length % i6 == 0 ? 0 : 1)) - i5;
                this.isWatchDialPause = false;
                next();
                return;
            }
            hashMap = new HashMap();
            hashMap.put("code", 0);
            hashMap.put("data", bArr);
            hashMap.put("dataType", 2304);
            bleDataResponse = this.sendingDataResponse;
            if (bleDataResponse != null) {
                if (bArr.length > 1) {
                    b2 = bArr[1];
                    bleDataResponse.onDataResponse(b2, 0.0f, hashMap);
                }
                bleDataResponse.onDataResponse(r4, 0.0f, hashMap);
            }
        }
        popQueue();
    }

    private void packetFactoryHandle(int i2, int i3, byte[] bArr, int i4) {
        HashMap hashMap = new HashMap();
        byte b2 = (bArr == null || bArr.length <= 2) ? (byte) 0 : bArr[2];
        if (i2 != 9) {
            return;
        }
        BleDataResponse bleDataResponse = this.sendingDataResponse;
        if (bleDataResponse != null) {
            try {
                bleDataResponse.onDataResponse(b2, 0.0f, hashMap);
            } catch (Exception e2) {
                e2.printStackTrace();
            }
        }
        popQueue();
    }

    /* JADX WARN: Code restructure failed: missing block: B:68:0x0109, code lost:
    
        if (r0 != null) goto L72;
     */
    /* JADX WARN: Code restructure failed: missing block: B:69:0x010b, code lost:
    
        r0.onDataResponse(1, 0.0f, null);
     */
    /* JADX WARN: Code restructure failed: missing block: B:94:0x0198, code lost:
    
        if (r0 != null) goto L72;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    private void packetGetHandle(int r17, int r18, byte[] r19, int r20) {
        /*
            Method dump skipped, instructions count: 999
            To view this dump change 'Code comments level' option to 'DEBUG'
        */
        throw new UnsupportedOperationException("Method not decompiled: com.yucheng.ycbtsdk.core.YCBTClientImpl.packetGetHandle(int, int, byte[], int):void");
    }

    /* JADX WARN: Code restructure failed: missing block: B:16:0x00d3, code lost:
    
        if (r12 != null) goto L31;
     */
    /* JADX WARN: Code restructure failed: missing block: B:17:0x00d5, code lost:
    
        r12.onDataResponse(0, 0.0f, null);
     */
    /* JADX WARN: Code restructure failed: missing block: B:35:0x00ce, code lost:
    
        if (r12 != null) goto L31;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    private void packetHealthHandle(int r12, int r13, byte[] r14, int r15) {
        /*
            Method dump skipped, instructions count: 478
            To view this dump change 'Code comments level' option to 'DEBUG'
        */
        throw new UnsupportedOperationException("Method not decompiled: com.yucheng.ycbtsdk.core.YCBTClientImpl.packetHealthHandle(int, int, byte[], int):void");
    }

    private void packetOTAHandle(int i2, int i3, byte[] bArr, int i4) {
        int i5;
        if (i2 != 0) {
            if (i2 != 1) {
                if (i2 != 2) {
                    return;
                }
                if (bArr.length >= 1 && bArr[0] == 0) {
                    nextOta();
                    return;
                }
                HashMap hashMap = new HashMap();
                int i6 = bArr[0] & 255;
                hashMap.put("code", 0);
                hashMap.put(ServerProtocol.DIALOG_PARAM_STATE, Integer.valueOf(i6));
                hashMap.put("dataType", 2560);
                BleDataResponse bleDataResponse = this.sendingDataResponse;
                if (bleDataResponse != null) {
                    bleDataResponse.onDataResponse(1, 0.0f, hashMap);
                    return;
                }
                return;
            }
            HashMap hashMap2 = new HashMap();
            hashMap2.put(ServerProtocol.DIALOG_PARAM_STATE, Integer.valueOf(bArr[0] & 255));
            BleDataResponse bleDataResponse2 = this.sendingDataResponse;
            if (bleDataResponse2 != null) {
                bleDataResponse2.onDataResponse(0, 0.0f, hashMap2);
            }
        } else {
            if (bArr.length >= 2 && bArr[0] == 1 && bArr[1] == 0) {
                byte[] bArr2 = this.mSendQueue.get(0).willData;
                if (bArr2 == null || bArr2.length <= 9 || (i5 = (bArr2[9] & 255) + ((bArr2[10] & 255) << 8)) == 255) {
                    i5 = 0;
                }
                this.otaIndex = 0;
                int i7 = this.otaSize;
                int i8 = i5 * i7;
                this.currentOtaIndex = i8;
                this.oldOtaIndex = i8;
                int length = otaDownloadData.length;
                this.otaLength = length;
                this.remainderOtaPackage = ((length / i7) + (length % i7 == 0 ? 0 : 1)) - i5;
                nextOta();
                return;
            }
            try {
                try {
                    HashMap unpackOTAData = DataUnpack.unpackOTAData(bArr);
                    dataResponse(((Integer) unpackOTAData.get("code")).intValue(), 0.0f, unpackOTAData);
                } catch (Exception e2) {
                    e2.printStackTrace();
                }
            } finally {
                popQueue();
            }
        }
    }

    private void packetOtaUIHandle(int i2, int i3, byte[] bArr, int i4) {
        try {
        } catch (Exception e2) {
            e2.printStackTrace();
        }
        if (i2 == 0) {
            if (this.sendingDataResponse != null) {
                this.sendingDataResponse.onDataResponse(0, 0.0f, DataUnpack.unpackUIFileBreakInfo(bArr));
            }
            popQueue();
        }
        if (i2 != 1) {
            if (i2 != 3) {
                return;
            }
            if (this.remainderPackage > 0 && bArr != null && bArr.length > 0 && bArr[0] == 0) {
                next();
                return;
            }
            if (this.sendingDataResponse != null) {
                byte b2 = bArr[0];
                HashMap hashMap = new HashMap();
                hashMap.put("code", 0);
                hashMap.put("dataType", 32259);
                hashMap.put("data", Integer.valueOf(b2));
                this.sendingDataResponse.onDataResponse(0, 0.0f, hashMap);
            }
            popQueue();
        }
        if (bArr != null && bArr.length > 0 && bArr[0] == 0) {
            try {
                YCSendBean yCSendBean = this.mSendQueue.get(0);
                if (SPUtil.getChipScheme() == 0) {
                    this.dialSize = 1024;
                } else {
                    this.dialSize = 4096;
                }
                this.dialIndex = 0;
                byte[] bArr2 = yCSendBean.willData;
                int i5 = (bArr2[12] & 255) + ((bArr2[13] & 255) << 8) + ((bArr2[14] & 255) << 16) + ((bArr2[15] & 255) << 24);
                this.currentDataIndex = i5;
                this.oldDataIndex = i5;
                int length = watchDialDownloadData.length;
                this.dialLength = length;
                int i6 = this.dialSize;
                this.remainderPackage = ((length / i6) + (length % i6 == 0 ? 0 : 1)) - (i5 / i6);
                this.isWatchDialPause = false;
                next();
                return;
            } catch (Exception e3) {
                e3.printStackTrace();
                return;
            }
        }
        if (this.sendingDataResponse != null) {
            byte b3 = bArr[0];
            HashMap hashMap2 = new HashMap();
            hashMap2.put("code", 0);
            hashMap2.put("dataType", 32257);
            hashMap2.put("data", Integer.valueOf(b3));
            this.sendingDataResponse.onDataResponse(0, 0.0f, hashMap2);
        }
        popQueue();
    }

    private void packetRealHandle(int i2, int i3, byte[] bArr, int i4) {
        HashMap unpackGetScheduleInfo;
        if (this.isRealData) {
            this.isRealData = false;
            BleDataResponse bleDataResponse = this.sendingDataResponse;
            if (bleDataResponse != null) {
                try {
                    bleDataResponse.onDataResponse(0, 0.0f, null);
                } catch (Exception e2) {
                    e2.printStackTrace();
                }
            }
        }
        try {
            switch (i2) {
                case 0:
                    if (this.mBleRealDataResponse != null) {
                        this.mBleRealDataResponse.onRealDataResponse(Constants.DATATYPE.Real_UploadSport, DataUnpack.unpackRealSportData(bArr));
                        return;
                    }
                    return;
                case 1:
                    if (this.mBleRealDataResponse != null) {
                        this.mBleRealDataResponse.onRealDataResponse(1537, DataUnpack.unpackRealHeartData(bArr));
                        return;
                    }
                    return;
                case 2:
                    if (this.mBleRealDataResponse != null) {
                        this.mBleRealDataResponse.onRealDataResponse(1538, DataUnpack.unpackRealBloodOxygenData(bArr));
                        return;
                    }
                    return;
                case 3:
                    if (this.mBleRealDataResponse != null) {
                        HashMap unpackRealBloodData = DataUnpack.unpackRealBloodData(bArr);
                        this.mBleRealDataResponse.onRealDataResponse(1539, unpackRealBloodData);
                        BleRealDataResponse bleRealDataResponse = this.mECGBleRealDataResponse;
                        if (bleRealDataResponse != null) {
                            bleRealDataResponse.onRealDataResponse(1539, unpackRealBloodData);
                        }
                        return;
                    }
                    return;
                case 4:
                    if (this.mBleRealDataResponse != null) {
                        HashMap unpackRealPPGData = DataUnpack.unpackRealPPGData(bArr);
                        this.mBleRealDataResponse.onRealDataResponse(Constants.DATATYPE.Real_UploadPPG, unpackRealPPGData);
                        BleRealDataResponse bleRealDataResponse2 = this.mECGBleRealDataResponse;
                        if (bleRealDataResponse2 != null) {
                            bleRealDataResponse2.onRealDataResponse(Constants.DATATYPE.Real_UploadPPG, unpackRealPPGData);
                        }
                        return;
                    }
                    return;
                case 5:
                    if (this.mBleRealDataResponse != null) {
                        HashMap unpackRealECGData = DataUnpack.unpackRealECGData(bArr);
                        this.mBleRealDataResponse.onRealDataResponse(Constants.DATATYPE.Real_UploadECG, unpackRealECGData);
                        BleRealDataResponse bleRealDataResponse3 = this.mECGBleRealDataResponse;
                        if (bleRealDataResponse3 != null) {
                            bleRealDataResponse3.onRealDataResponse(Constants.DATATYPE.Real_UploadECG, unpackRealECGData);
                        }
                        return;
                    }
                    return;
                case 6:
                    if (this.mBleRealDataResponse != null) {
                        this.mBleRealDataResponse.onRealDataResponse(1537, DataUnpack.unpackRealUploadRunData(bArr));
                        return;
                    }
                    return;
                case 7:
                    if (this.mBleRealDataResponse != null) {
                        this.mBleRealDataResponse.onRealDataResponse(Constants.DATATYPE.Real_UploadRespiratoryRate, DataUnpack.unpackRealRespiratoryRateData(bArr));
                        return;
                    }
                    return;
                case 8:
                    if (this.mBleRealDataResponse != null) {
                        this.mBleRealDataResponse.onRealDataResponse(Constants.DATATYPE.Real_UploadSensor, DataUnpack.unpackRealSensorData(bArr));
                        return;
                    }
                    return;
                case 9:
                    if (this.mBleRealDataResponse != null) {
                        this.mBleRealDataResponse.onRealDataResponse(Constants.DATATYPE.Real_UploadAmbientlight, DataUnpack.unpackRealAmbientlightData(bArr));
                        return;
                    }
                    return;
                case 10:
                    if (this.mBleRealDataResponse != null) {
                        this.mBleRealDataResponse.onRealDataResponse(Constants.DATATYPE.Real_UploadComprehensive, DataUnpack.unpackRealComprehensiveData(bArr));
                        return;
                    }
                    return;
                case 11:
                    if (bArr.length >= 9 && this.sendingDataResponse != null) {
                        unpackGetScheduleInfo = DataUnpack.unpackGetScheduleInfo(bArr);
                        break;
                    } else {
                        return;
                    }
                    break;
                case 12:
                    if (bArr.length >= 6 && this.sendingDataResponse != null) {
                        unpackGetScheduleInfo = DataUnpack.unpackGetEventReminder(bArr);
                        break;
                    } else {
                        return;
                    }
                    break;
                case 13:
                    if (this.mBleRealDataResponse != null) {
                        this.mBleRealDataResponse.onRealDataResponse(Constants.DATATYPE.Real_UploadOGA, DataUnpack.unpackGetUploadOGA(bArr));
                        return;
                    }
                    return;
                case 14:
                    if (this.mBleRealDataResponse != null) {
                        this.mBleRealDataResponse.onRealDataResponse(Constants.DATATYPE.Real_UploadInflatedBlood, DataUnpack.unpackGetInflatedBlood(bArr));
                        return;
                    }
                    return;
                case 15:
                    if (this.mBleRealDataResponse != null) {
                        this.mBleRealDataResponse.onRealDataResponse(Constants.DATATYPE.Real_UploadMulPhotoelectricWaveform, DataUnpack.unpackMulPhotoelectricWaveform(bArr));
                        return;
                    }
                    return;
                case 16:
                    if (this.mBleRealDataResponse != null) {
                        this.mBleRealDataResponse.onRealDataResponse(Constants.DATATYPE.Real_UploadBodyData, DataUnpack.unpackBodyData(bArr));
                        return;
                    }
                    return;
                default:
                    return;
            }
            this.scheduleInfos.add(unpackGetScheduleInfo);
        } catch (Exception e3) {
            e3.printStackTrace();
        }
    }

    private void packetSelfInspectionHandle(int i2, int i3, byte[] bArr, int i4) {
        if (i2 != 0) {
            return;
        }
        HashMap hashMap = new HashMap();
        int i5 = bArr[0] & 255;
        byte b2 = bArr[1];
        int i6 = bArr[2] & 1;
        hashMap.put("code", Integer.valueOf(i5));
        hashMap.put("TP", Integer.valueOf((b2 >> 7) & 1));
        hashMap.put("TEMP", Integer.valueOf((b2 >> 6) & 1));
        hashMap.put("ECG", Integer.valueOf((b2 >> 5) & 1));
        hashMap.put("PPG_IR", Integer.valueOf((b2 >> 4) & 1));
        hashMap.put("PPG_R", Integer.valueOf((b2 >> 3) & 1));
        hashMap.put("PPG_G", Integer.valueOf((b2 >> 2) & 1));
        hashMap.put("PPG", Integer.valueOf((b2 >> 1) & 1));
        hashMap.put("GS", Integer.valueOf(b2 & 1));
        hashMap.put("LCD", Integer.valueOf(i6));
        BleDataResponse bleDataResponse = this.sendingDataResponse;
        if (bleDataResponse != null) {
            try {
                bleDataResponse.onDataResponse(0, 0.0f, hashMap);
            } catch (Exception e2) {
                e2.printStackTrace();
            }
        }
        popQueue();
    }

    /* JADX WARN: Code restructure failed: missing block: B:18:0x0047, code lost:
    
        if (r5 != null) goto L25;
     */
    /* JADX WARN: Code restructure failed: missing block: B:26:0x004c, code lost:
    
        if (r5 != null) goto L25;
     */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:36:0x0077 -> B:20:0x007a). Please report as a decompilation issue!!! */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    private void packetSettingHandle(int r5, int r6, byte[] r7, int r8) {
        /*
            r4 = this;
            r6 = 0
            r8 = 0
            if (r7 == 0) goto L40
            int r0 = r7.length
            if (r0 <= 0) goto La
            r0 = r7[r6]
            goto Lb
        La:
            r0 = r6
        Lb:
            int r1 = r7.length
            r2 = 1
            if (r1 <= r2) goto L3d
            java.util.HashMap r1 = new java.util.HashMap
            r1.<init>()
            r2 = r7[r2]
            java.lang.Byte r2 = java.lang.Byte.valueOf(r2)
            java.lang.String r3 = "data"
            r1.put(r3, r2)
            java.util.concurrent.CopyOnWriteArrayList<com.yucheng.ycbtsdk.core.YCSendBean> r2 = r4.mSendQueue
            if (r2 == 0) goto L3e
            int r2 = r2.size()
            if (r2 <= 0) goto L3e
            java.util.concurrent.CopyOnWriteArrayList<com.yucheng.ycbtsdk.core.YCSendBean> r2 = r4.mSendQueue
            java.lang.Object r6 = r2.get(r6)
            com.yucheng.ycbtsdk.core.YCSendBean r6 = (com.yucheng.ycbtsdk.core.YCSendBean) r6
            int r6 = r6.dataType
            java.lang.Integer r6 = java.lang.Integer.valueOf(r6)
            java.lang.String r2 = "dataType"
            r1.put(r2, r6)
            goto L3e
        L3d:
            r1 = r8
        L3e:
            r6 = r0
            goto L41
        L40:
            r1 = r8
        L41:
            r0 = 0
            switch(r5) {
                case 0: goto L60;
                case 1: goto L54;
                case 2: goto L4a;
                case 3: goto L4a;
                case 4: goto L4a;
                case 5: goto L4a;
                case 6: goto L4a;
                case 7: goto L45;
                case 8: goto L4a;
                case 9: goto L4a;
                case 10: goto L4a;
                case 11: goto L4a;
                case 12: goto L4a;
                case 13: goto L4a;
                case 14: goto L4a;
                case 15: goto L4a;
                case 16: goto L45;
                case 17: goto L45;
                case 18: goto L4a;
                case 19: goto L4a;
                case 20: goto L4a;
                case 21: goto L4a;
                case 22: goto L4a;
                case 23: goto L45;
                case 24: goto L45;
                case 25: goto L4a;
                case 26: goto L4a;
                case 27: goto L4a;
                case 28: goto L45;
                case 29: goto L45;
                case 30: goto L4a;
                case 31: goto L4a;
                case 32: goto L4a;
                case 33: goto L4a;
                case 34: goto L4a;
                case 35: goto L4a;
                case 36: goto L4a;
                case 37: goto L4a;
                case 38: goto L4a;
                case 39: goto L4a;
                case 40: goto L4a;
                case 41: goto L4a;
                case 42: goto L4a;
                case 43: goto L4a;
                case 44: goto L4a;
                case 45: goto L4a;
                case 46: goto L4a;
                case 47: goto L4a;
                case 48: goto L4a;
                case 49: goto L4a;
                case 50: goto L4a;
                case 51: goto L4a;
                case 52: goto L4a;
                case 53: goto L4a;
                case 54: goto L4a;
                case 55: goto L4a;
                case 56: goto L4a;
                case 57: goto L4a;
                case 58: goto L4a;
                case 59: goto L4a;
                case 60: goto L4a;
                case 61: goto L4a;
                case 62: goto L4a;
                case 63: goto L45;
                case 64: goto L45;
                case 65: goto L45;
                case 66: goto L45;
                case 67: goto L45;
                case 68: goto L45;
                case 69: goto L4a;
                case 70: goto L4a;
                case 71: goto L45;
                case 72: goto L4a;
                default: goto L45;
            }
        L45:
            com.yucheng.ycbtsdk.response.BleDataResponse r5 = r4.sendingDataResponse
            if (r5 == 0) goto L7a
            goto L4e
        L4a:
            com.yucheng.ycbtsdk.response.BleDataResponse r5 = r4.sendingDataResponse
            if (r5 == 0) goto L7a
        L4e:
            r5.onDataResponse(r6, r0, r1)     // Catch: java.lang.Exception -> L52
            goto L7a
        L52:
            r5 = move-exception
            goto L77
        L54:
            com.yucheng.ycbtsdk.response.BleDataResponse r5 = r4.sendingDataResponse
            if (r5 == 0) goto L7a
            java.util.HashMap r7 = com.yucheng.ycbtsdk.core.DataUnpack.unpackAlarmData(r7)     // Catch: java.lang.Exception -> L52
            r5.onDataResponse(r6, r0, r7)     // Catch: java.lang.Exception -> L52
            goto L7a
        L60:
            com.yucheng.ycbtsdk.response.BleDataResponse r5 = r4.sendingDataResponse
            if (r5 == 0) goto L65
            goto L4e
        L65:
            int r5 = r4.mBleStateCode
            r6 = 9
            if (r5 != r6) goto L7a
            r5 = 2
            byte[] r6 = new byte[r5]
            r6 = {x0114: FILL_ARRAY_DATA , data: [71, 70} // fill-array
            r7 = 513(0x201, float:7.19E-43)
            r4.sendSingleData2Device(r7, r6, r5, r8)
            goto L7a
        L77:
            r5.printStackTrace()
        L7a:
            r4.popQueue()
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.yucheng.ycbtsdk.core.YCBTClientImpl.packetSettingHandle(int, int, byte[], int):void");
    }

    private void packetTestToolHandle(int i2, int i3, byte[] bArr, int i4) {
        try {
        } catch (Exception e2) {
            e2.printStackTrace();
        }
        if (i2 == 4) {
            if (this.mBleRealDataResponse != null) {
                this.mBleRealDataResponse.onRealDataResponse(Constants.DATATYPE.Gsensor, DataUnpack.unpackRealGsensorData(bArr));
            }
            popQueue();
        }
        byte b2 = 0;
        HashMap hashMap = null;
        if (bArr != null) {
            byte b3 = bArr.length > 0 ? bArr[0] : (byte) 0;
            if (bArr.length > 1) {
                hashMap = new HashMap();
                hashMap.put("data", Byte.valueOf(bArr[1]));
                CopyOnWriteArrayList<YCSendBean> copyOnWriteArrayList = this.mSendQueue;
                if (copyOnWriteArrayList != null && copyOnWriteArrayList.size() > 0) {
                    hashMap.put("dataType", Integer.valueOf(this.mSendQueue.get(0).dataType));
                }
            }
            b2 = b3;
        }
        BleDataResponse bleDataResponse = this.sendingDataResponse;
        if (bleDataResponse != null) {
            bleDataResponse.onDataResponse(b2, 0.0f, hashMap);
        }
        popQueue();
        popQueue();
    }

    private void pauseDial() {
        this.isWatchDialPause = false;
        stopDial();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void popQueue() {
        synchronized (this) {
            if (this.mSendQueue.size() > 0) {
                YCBTLog.e("popQueue Gatt写回调 " + this.isGattWriteCallBackFinish);
                if (this.isGattWriteCallBackFinish) {
                    removeTimeout();
                    this.mSendQueue.remove(0);
                    this.mQueueSendState = false;
                    Collections.sort(this.mSendQueue);
                    YCBTLog.e("排序后 " + this.mSendQueue);
                    YCBTLog.e("popQueue 队列剩余大小 " + this.mSendQueue.size() + " " + this.mSendQueue + " 实时测试 " + this.isRecvRealEcging + " mQueueSendState " + this.mQueueSendState);
                    if (!this.isRecvRealEcging) {
                        frontQueue();
                    }
                } else {
                    this.mSendQueue.get(0).dataSendFinish = true;
                }
            }
        }
    }

    public static void setOtaDownloadData(byte[] bArr) {
        otaDownloadData = bArr;
    }

    public static void setWatchDialDownloadData(byte[] bArr) {
        watchDialDownloadData = bArr;
    }

    private void stopDial() {
        int i2 = this.dialLength;
        sendData2Device(2304, new byte[]{0, (byte) i2, (byte) (i2 >> 8), (byte) (i2 >> 16), (byte) (i2 >> 24)});
    }

    @Override // com.yucheng.ycbtsdk.gatt.GattBleResponse
    public void bleDataResponse(int i2, byte[] bArr, String str) {
        int i3;
        int i4;
        int i5;
        int i6;
        if (CMD.JL_UUID_NOTIFICATION.equals(str)) {
            if (this.isOta && YCBTClient.getAuthPass()) {
                JLOTAManager.getInstance(this.context).onOtaReceiveDeviceData(getGatt().getDevice(), bArr);
                return;
            } else {
                WatchManager.getInstance().onReceiveData(getGatt().getDevice(), bArr);
                return;
            }
        }
        if (bArr == null) {
            return;
        }
        boolean z = this.isFlag;
        if (z) {
            i3 = 0;
            i4 = 0;
            i5 = 0;
            i6 = 0;
        } else {
            if (bArr.length < 6) {
                return;
            }
            i3 = bArr[0] & 255;
            i4 = bArr[1] & 255;
            i5 = (bArr[2] & 255) + ((bArr[3] & 255) << 8);
            i6 = 4;
        }
        if (i5 != bArr.length) {
            if (!z && bArr.length != BleHelper.MTU - 3) {
                return;
            }
            this.isFlag = true;
            YCBTLog.e("BLE datas == " + ByteUtil.byteToString(bArr) + " 返回长度有问题：cmdlen = " + i5 + "byteLen == " + bArr.length);
            byte[] bArr2 = this.datas;
            if (bArr2 == null) {
                this.datas = bArr;
                return;
            }
            int length = bArr2.length + bArr.length;
            byte[] bArr3 = new byte[length];
            System.arraycopy(bArr2, 0, bArr3, 0, bArr2.length);
            System.arraycopy(bArr, 0, bArr3, this.datas.length, bArr.length);
            YCBTLog.e("BLE datas == " + ByteUtil.byteToString(bArr3));
            i3 = bArr3[0] & 255;
            int i7 = bArr3[1] & 255;
            int i8 = (bArr3[2] & 255) + ((bArr3[3] & 255) << 8);
            if (i8 == length) {
                this.isFlag = false;
                bArr = bArr3;
            } else {
                if (i8 > length) {
                    this.datas = null;
                    this.isFlag = false;
                    return;
                }
                this.datas = bArr3;
            }
            i4 = i7;
            i6 = 4;
            i5 = i8;
        }
        int i9 = ((bArr[i5 - 2] & 255) << 8) + (bArr[i5 - 1] & 255);
        int i10 = i5 - 6;
        byte[] bArr4 = new byte[i10];
        System.arraycopy(bArr, i6, bArr4, 0, i10);
        CopyOnWriteArrayList<YCSendBean> copyOnWriteArrayList = this.mSendQueue;
        if (copyOnWriteArrayList != null && copyOnWriteArrayList.size() > 0) {
            if (this.mSendQueue.get(0).dataType == (i3 << 8) + i4) {
                removeTimeout();
            }
        }
        if (3 != i3 && isError(bArr4)) {
            YCBTLog.e("isError--" + ((int) bArr4[0]));
            if (i3 == 4 || i3 == 6) {
                return;
            }
            if (this.mTimeOutHander != null && this.mTimeRunnable != null) {
                removeTimeout();
            }
            if (this.mBleStateCode == 9 && i3 == 2 && i4 == 27) {
                SPUtil.saveChipScheme(0);
                sendSingleData2Device(512, new byte[]{JSONB.Constants.BC_INT32_SHORT_MAX, 67}, 2, null);
            }
            dataResponse(bArr4[0], 0.0f, null);
            popQueue();
            return;
        }
        if (i3 == 19) {
            packetCollectionToolsHandle(i4, i10, bArr4, i9);
            return;
        }
        if (i3 == 126) {
            packetOtaUIHandle(i4, i10, bArr4, i9);
            return;
        }
        switch (i3) {
            case 1:
                packetSettingHandle(i4, i10, bArr4, i9);
                return;
            case 2:
                break;
            case 3:
                packetAppControlHandle(i4, i10, bArr4, i9);
                return;
            case 4:
                packetDevControlHandle(i4, i10, bArr4, i9);
                return;
            case 5:
                packetHealthHandle(i4, i10, bArr4, i9);
                return;
            case 6:
                packetRealHandle(i4, i10, bArr4, i9);
                return;
            case 7:
                packetCollectHandle(i4, i10, bArr4, i9);
                return;
            case 8:
                packetFactoryHandle(i4, i10, bArr4, i9);
                return;
            case 9:
                packetDialHandle(i4, i10, bArr4, i9);
                return;
            case 10:
                packetOTAHandle(i4, i10, bArr4, i9);
                return;
            default:
                switch (i3) {
                    case 12:
                        packetSelfInspectionHandle(i4, i10, bArr4, i9);
                        break;
                    case 13:
                        packetCustomizeHandle(i4, i10, bArr4, i9);
                        break;
                    case 14:
                        packetTestToolHandle(i4, i10, bArr4, i9);
                        break;
                }
                return;
        }
        packetGetHandle(i4, i10, bArr4, i9);
    }

    @Override // com.yucheng.ycbtsdk.gatt.GattBleResponse
    public void bleOnCharacteristicWrite(int i2, byte[] bArr, String str) {
        byte b2;
        if (CMD.JL_UUID_WRITE.equals(str)) {
            this.isGattWriteCallBackFinish = true;
            popQueue();
            return;
        }
        if (bArr != null && bArr.length >= 2 && (((b2 = bArr[0]) == 9 && bArr[1] == 1) || (b2 == 126 && bArr[1] == 2))) {
            next();
            return;
        }
        if (bArr != null && bArr.length >= 2 && bArr[0] == 10 && bArr[1] == 1) {
            nextOta();
            return;
        }
        this.isGattWriteCallBackFinish = true;
        CopyOnWriteArrayList<YCSendBean> copyOnWriteArrayList = this.mSendQueue;
        if (copyOnWriteArrayList == null || copyOnWriteArrayList.size() <= 0) {
            return;
        }
        YCSendBean yCSendBean = this.mSendQueue.get(0);
        if (i2 == 257) {
            yCSendBean.dataSendFinish = true;
        } else if (!yCSendBean.dataSendFinish) {
            frontQueue();
            return;
        }
        popQueue();
    }

    @Override // com.yucheng.ycbtsdk.gatt.GattBleResponse
    public void bleScanListResponse(int i2, List<ScanDeviceBean> list) {
        BleScanListResponse bleScanListResponse = this.mBleScanListResponse;
        if (bleScanListResponse != null) {
            bleScanListResponse.onScanListResponse(i2, list);
        }
    }

    @Override // com.yucheng.ycbtsdk.gatt.GattBleResponse
    public void bleScanResponse(int i2, ScanDeviceBean scanDeviceBean) {
        BleScanResponse bleScanResponse = this.mBleScanResponse;
        if (bleScanResponse != null) {
            bleScanResponse.onScanResponse(i2, scanDeviceBean);
        }
        if (i2 != 0) {
            stopScanBle();
        }
    }

    @Override // com.yucheng.ycbtsdk.gatt.GattBleResponse
    public void bleStateResponse(int i2) {
        BleConnectResponse bleConnectResponse;
        BleConnectResponse bleConnectResponse2;
        YCBTLog.e("connectState==" + i2);
        if (i2 == 6) {
            this.isRecvRealEcging = false;
            resetQueue();
        }
        this.mBleStateCode = i2;
        if (i2 == 10) {
            try {
                BleHelper.getHelper().isConnecting = false;
                Reconnect.getInstance().resetReconnectTime();
            } catch (Exception e2) {
                e2.printStackTrace();
            }
        }
        Iterator<BleConnectResponse> it2 = this.mBleStatelistens.iterator();
        while (it2.hasNext()) {
            it2.next().onConnectResponse(this.mBleStateCode);
        }
        if (this.mBleStateCode == 10 && (bleConnectResponse2 = this.mBleConnectResponse) != null) {
            bleConnectResponse2.onConnectResponse(0);
        }
        if (this.mBleStateCode <= 3 && (bleConnectResponse = this.mBleConnectResponse) != null) {
            bleConnectResponse.onConnectResponse(1);
        }
        if (this.mBleStateCode == 9) {
            if (this.isForceOta) {
                WatchManager.getInstance().initWatchManager(this.context);
                YCBTLog.e("onDescriptorWrite  开始认证 ");
                WatchManager.getInstance().setReAuthPass(new BleDataResponse() { // from class: com.yucheng.ycbtsdk.core.YCBTClientImpl.7
                    @Override // com.yucheng.ycbtsdk.response.BleDataResponse
                    public void onDataResponse(int i3, float f2, HashMap hashMap) {
                        if (i3 == 0) {
                            YCBTClientImpl.this.bleStateResponse(10);
                        }
                    }
                });
            } else {
                if (this.isOta) {
                    sendSingleData2Device(539, new byte[0], 2, null);
                    return;
                }
                YCBTClient.getDeviceName(null);
                if (this.isTool) {
                    sendSingleData2Device(513, new byte[]{JSONB.Constants.BC_INT32_SHORT_MAX, 70}, 2, null);
                } else {
                    sendSingleData2Device(256, TimeUtil.makeBleTime(), 2, null);
                }
            }
        }
    }

    public void connectBle(String str, String str2, long j2, BleConnectResponse bleConnectResponse) {
        if (bleConnectResponse != null) {
            this.mBleConnectResponse = bleConnectResponse;
        }
        YCBTLog.e("connectBle isRepeat = true");
        BleHelper.getHelper().connectGatt(str, str2, true, j2);
    }

    public void connectBle(String str, String str2, BleConnectResponse bleConnectResponse) {
        connectBle(str, str2, 15000L, bleConnectResponse);
    }

    public int connectState() {
        return this.mBleStateCode;
    }

    public void disconnectBle() {
        SPUtil.saveBindedDeviceMac("");
        BleHelper.getHelper().disconnectGatt();
    }

    public BluetoothGatt getGatt() {
        return BleHelper.getHelper().mBluetoothGatt;
    }

    public int getQueueSize() {
        CopyOnWriteArrayList<YCSendBean> copyOnWriteArrayList = this.mSendQueue;
        if (copyOnWriteArrayList != null) {
            return copyOnWriteArrayList.size();
        }
        return 0;
    }

    public BleDeviceToAppDataResponse getmBleDeviceToAppResponse() {
        return this.mBleDeviceToAppResponse;
    }

    public void init(Context context, boolean z, boolean z2) {
        this.context = context;
        SPUtil.init(context);
        BleHelper.getHelper().initContext(context);
        BleHelper.getHelper().registerGattResponse(this);
        this.mSendQueue = new CopyOnWriteArrayList<>();
        this.mQueueSendState = false;
        this.mBlockArray = new ArrayList();
        this.mLastBlockArray = new ArrayList();
        this.mBleStatelistens = new ArrayList<>();
        this.mTimeOutHander = new Handler();
        Reconnect.getInstance().init(context, z);
        LogToFileUtils.init(context);
        YCBTClient.OpenLogSwitch = z2;
    }

    public void jniCallback(int i2, float f2) {
        HashMap hashMap = new HashMap();
        hashMap.put("code", 0);
        hashMap.put("data", Float.valueOf(f2));
        try {
            if (i2 == 3) {
                hashMap.put("dataType", Integer.valueOf(Constants.DATATYPE.Real_UploadECGRR));
                if (this.mBleRealDataResponse != null) {
                    YCBTLog.e("RR值 " + this.mBleRealDataResponse + " " + hashMap);
                    this.mBleRealDataResponse.onRealDataResponse(Constants.DATATYPE.Real_UploadECGRR, hashMap);
                }
                if (this.mECGBleRealDataResponse != null) {
                    YCBTLog.e("RR值 " + this.mECGBleRealDataResponse + " " + hashMap);
                    this.mECGBleRealDataResponse.onRealDataResponse(Constants.DATATYPE.Real_UploadECGRR, hashMap);
                    return;
                }
                return;
            }
            if (i2 != 4) {
                return;
            }
            hashMap.put("dataType", Integer.valueOf(Constants.DATATYPE.Real_UploadECGHrv));
            BleRealDataResponse bleRealDataResponse = this.mBleRealDataResponse;
            if (bleRealDataResponse != null) {
                bleRealDataResponse.onRealDataResponse(Constants.DATATYPE.Real_UploadECGHrv, hashMap);
            }
            BleRealDataResponse bleRealDataResponse2 = this.mECGBleRealDataResponse;
            if (bleRealDataResponse2 != null) {
                bleRealDataResponse2.onRealDataResponse(Constants.DATATYPE.Real_UploadECGHrv, hashMap);
            }
        } catch (Exception e2) {
            e2.printStackTrace();
        }
    }

    public void pushQueue(YCSendBean yCSendBean) {
        int i2;
        synchronized (this) {
            if (!this.isForceOta || (i2 = yCSendBean.dataType) == 43690 || i2 == 52428) {
                YCBTLog.e("pushQueue isRecvRealEcging=" + this.isRecvRealEcging + " sendBean.groupType=" + yCSendBean.groupType + " mSendQueue.size()=" + this.mSendQueue.size());
                if (yCSendBean.groupType == 11 && !this.isRecvRealEcging) {
                    Iterator<YCSendBean> it2 = this.mSendQueue.iterator();
                    while (it2.hasNext()) {
                        YCSendBean next = it2.next();
                        if (next.groupType == 10) {
                            try {
                                YCBTLog.e("把开始ECG指令从队列移除");
                                this.mSendQueue.remove(next);
                            } catch (Exception e2) {
                                e2.printStackTrace();
                            }
                        }
                    }
                }
                this.mSendQueue.add(yCSendBean);
                try {
                    YCBTLog.e("pushQueue 队列剩余大小 " + this.mSendQueue.size() + " " + this.mSendQueue + " 实时测试 " + this.isRecvRealEcging + " mQueueSendState " + this.mQueueSendState);
                } catch (Exception e3) {
                    e3.printStackTrace();
                }
                if (yCSendBean.groupType == 11) {
                    YCBTLog.e("pushQueue CMD.Group.Group_EndEcgTest");
                    Collections.sort(this.mSendQueue);
                    YCBTLog.e("排序后 " + this.mSendQueue);
                    frontQueue();
                    this.mEndEcgTimeOutCount = 0;
                    this.mTimeOutHander.removeCallbacks(this.mEndEcgTestOut);
                    this.mTimeOutHander.postDelayed(this.mEndEcgTestOut, 2500L);
                } else if (!this.mQueueSendState && !this.isRecvRealEcging) {
                    frontQueue();
                }
            }
        }
    }

    public void registerBleStateChangeCallBack(BleConnectResponse bleConnectResponse) {
        if (this.mBleStatelistens == null) {
            this.mBleStatelistens = new ArrayList<>();
        }
        this.mBleStatelistens.add(bleConnectResponse);
    }

    public void registerEcgRealDataCallBack(BleRealDataResponse bleRealDataResponse) {
        this.mECGBleRealDataResponse = bleRealDataResponse;
    }

    public void registerRealDataCallBack(BleRealDataResponse bleRealDataResponse) {
        this.mBleRealDataResponse = bleRealDataResponse;
    }

    public void registerRealTypeCallBack(BleDeviceToAppDataResponse bleDeviceToAppDataResponse) {
        this.mBleDeviceToAppResponse = bleDeviceToAppDataResponse;
    }

    public void removeTimeout() {
        this.mTimeOutHander.removeCallbacks(this.mTimeRunnable);
        this.mEndTimeOutCount = 0;
    }

    public void resetQueue() {
        YCBTLog.e("resetQueue");
        this.mQueueSendState = false;
        this.isRecvRealEcging = false;
        this.isGattWriteCallBackFinish = true;
        if (this.mSendQueue == null) {
            this.mSendQueue = new CopyOnWriteArrayList<>();
        }
        this.mSendQueue.clear();
    }

    public void sendData2Device(final int i2, byte[] bArr) {
        int length = bArr.length + 6;
        final byte[] bArr2 = new byte[length];
        bArr2[0] = (byte) ((i2 >> 8) & 255);
        bArr2[1] = (byte) (i2 & 255);
        bArr2[2] = (byte) (length & 255);
        bArr2[3] = (byte) ((length >> 8) & 255);
        int i3 = length - 6;
        System.arraycopy(bArr, 0, bArr2, 4, i3);
        int i4 = i3 + 4;
        int crc16_compute = ByteUtil.crc16_compute(bArr2, length - 2);
        bArr2[i4] = (byte) (crc16_compute & 255);
        bArr2[i4 + 1] = (byte) ((crc16_compute >> 8) & 255);
        this.isGattWriteCallBackFinish = false;
        new Thread(new Runnable() { // from class: com.yucheng.ycbtsdk.core.YCBTClientImpl.4
            @Override // java.lang.Runnable
            public void run() {
                if (i2 == 2561) {
                    BleHelper.getHelper().gatt2WriteData(bArr2);
                    return;
                }
                try {
                    Thread.sleep(30L);
                } catch (Exception e2) {
                    e2.printStackTrace();
                }
                if (i2 == 2305 || (SPUtil.getChipScheme() != 0 && i2 == 32258)) {
                    BleHelper.getHelper().gatt2WriteData(bArr2);
                } else {
                    BleHelper.getHelper().gattWriteData(bArr2);
                }
            }
        }).start();
    }

    public void sendDataType2Device(int i2, int i3, byte[] bArr, int i4, BleDataResponse bleDataResponse) {
        YCSendBean yCSendBean = new YCSendBean(bArr, i4, bleDataResponse);
        yCSendBean.groupType = i3;
        yCSendBean.dataType = i2;
        pushQueue(yCSendBean);
    }

    public void sendSingleData2Device(int i2, byte[] bArr, int i3, BleDataResponse bleDataResponse) {
        YCSendBean yCSendBean = new YCSendBean(bArr, i3, bleDataResponse);
        yCSendBean.dataType = i2;
        yCSendBean.groupType = 1;
        if (i2 != 2304 || bArr.length <= 0 || bArr[0] != 0) {
            if (i2 == 32257) {
                Iterator<YCSendBean> it2 = this.mSendQueue.iterator();
                while (it2.hasNext()) {
                    if (it2.next().dataType == 32257) {
                        this.sendingDataResponse = bleDataResponse;
                        return;
                    }
                }
            }
            pushQueue(yCSendBean);
            return;
        }
        if (this.mSendQueue.size() > 0 && this.mSendQueue.get(0).dataType == 2304) {
            this.isWatchDialPause = true;
            return;
        }
        Iterator<YCSendBean> it3 = this.mSendQueue.iterator();
        while (it3.hasNext()) {
            YCSendBean next = it3.next();
            if (next.dataType == 2304) {
                this.mSendQueue.remove(next);
            }
        }
    }

    public void setForceOta(boolean z) {
        this.isForceOta = z;
    }

    public void setOta(boolean z) {
        this.isOta = z;
    }

    public void setmBleConnectResponse(BleConnectResponse bleConnectResponse) {
        this.mBleConnectResponse = bleConnectResponse;
    }

    public void startScanBle(BleScanListResponse bleScanListResponse, int i2) {
        this.mBleScanListResponse = bleScanListResponse;
        YCBTLog.e("startScanBle timeoutSec=" + i2 + " scanResponse=" + bleScanListResponse);
        this.mTimeOutHander.removeCallbacks(this.mTimerOutRunnable);
        this.mTimeOutHander.postDelayed(this.mTimerOutRunnable, i2 * 1000);
        BleHelper.getHelper().startScan(i2);
    }

    public void startScanBle(BleScanResponse bleScanResponse, int i2) {
        this.mBleScanResponse = bleScanResponse;
        YCBTLog.e("startScanBle timeoutSec=" + i2 + " scanResponse=" + bleScanResponse);
        this.mTimeOutHander.removeCallbacks(this.mTimerOutRunnable);
        this.mTimeOutHander.postDelayed(this.mTimerOutRunnable, i2 * 1000);
        BleHelper.getHelper().startScan(i2);
    }

    public void stopScanBle() {
        Handler handler = this.mTimeOutHander;
        if (handler != null) {
            handler.removeCallbacks(this.mTimerOutRunnable);
        }
        BleHelper.getHelper().stopScan();
        BleScanResponse bleScanResponse = this.mBleScanResponse;
        if (bleScanResponse != null) {
            bleScanResponse.onScanResponse(2, null);
            this.mBleScanResponse = null;
        }
        BleScanListResponse bleScanListResponse = this.mBleScanListResponse;
        if (bleScanListResponse != null) {
            bleScanListResponse.onScanListResponse(2, null);
            this.mBleScanListResponse = null;
        }
    }

    public void unRegisterRealDataCallBack(BleRealDataResponse bleRealDataResponse) {
        this.mBleRealDataResponse = bleRealDataResponse;
    }

    public void unregisterBleStateChangeCallBack(BleConnectResponse bleConnectResponse) {
        if (this.mBleStatelistens.contains(bleConnectResponse)) {
            this.mBleStatelistens.remove(bleConnectResponse);
        }
    }
}
