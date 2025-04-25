package com.yucheng.smarthealthpro.home.activity.sleep.activity;

import android.content.Context;
import android.content.Intent;
import android.graphics.Color;
import android.os.Bundle;
import android.text.Html;
import android.text.SpannableString;
import android.text.style.AbsoluteSizeSpan;
import android.text.style.ForegroundColorSpan;
import android.view.View;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.core.content.res.ResourcesCompat;
import androidx.core.widget.NestedScrollView;
import androidx.fragment.app.Fragment;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewpager.widget.ViewPager;
import butterknife.BindView;
import butterknife.ButterKnife;
import butterknife.OnClick;
import butterknife.Unbinder;
import com.flyco.tablayout.SlidingTabLayout;
import com.google.android.material.timepicker.TimeModel;
import com.google.firebase.crashlytics.buildtools.reloc.org.apache.commons.cli.HelpFormatter;
import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import com.haibin.calendarview.Calendar;
import com.haibin.calendarview.CalendarView;
import com.orhanobut.logger.Logger;
import com.yucheng.smarthealthpro.base.BaseActivity;
import com.yucheng.smarthealthpro.care.bean.CareSleepWeekMonthBean;
import com.yucheng.smarthealthpro.care.bean.HistorySleepResponse;
import com.yucheng.smarthealthpro.framework.http.HttpUtils;
import com.yucheng.smarthealthpro.framework.util.Constants;
import com.yucheng.smarthealthpro.framework.view.NavigationBar;
import com.yucheng.smarthealthpro.greendao.bean.SleepDb;
import com.yucheng.smarthealthpro.greendao.utils.SleepDbUtils;
import com.yucheng.smarthealthpro.home.activity.HealthyActivity;
import com.yucheng.smarthealthpro.home.activity.sleep.adapter.SleepHisListAdapter;
import com.yucheng.smarthealthpro.home.activity.sleep.adapter.SleepTabFragmentAdapter;
import com.yucheng.smarthealthpro.home.activity.sleep.bean.SleepDayInfo;
import com.yucheng.smarthealthpro.home.activity.sleep.bean.SleepHisListBean;
import com.yucheng.smarthealthpro.home.activity.sleep.fragment.Sleep2TabFragment;
import com.yucheng.smarthealthpro.home.util.TimeDateUtil;
import com.yucheng.smarthealthpro.home.view.NoScrollViewPager;
import com.yucheng.smarthealthpro.me.activity.MeHealthSettingActivity;
import com.yucheng.smarthealthpro.me.setting.contacts.utils.DpUtil;
import com.yucheng.smarthealthpro.utils.AppDateMgr;
import com.yucheng.smarthealthpro.utils.AppScreenMgr;
import com.yucheng.smarthealthpro.utils.Constant;
import com.yucheng.smarthealthpro.utils.DensityUtils;
import com.yucheng.smarthealthpro.utils.FormatUtil;
import com.yucheng.smarthealthpro.utils.ShareUtils;
import com.yucheng.smarthealthpro.utils.TimeStampUtils;
import com.yucheng.smarthealthpro.utils.Tools;
import com.yucheng.smarthealthpro.utils.YearToDayListUtils;
import com.zhuoting.healthyucheng.R;
import io.github.inflationx.viewpump.ViewPumpContextWrapper;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;

/* loaded from: classes3.dex */
public class Sleep2Activity extends BaseActivity implements CalendarView.OnCalendarSelectListener, CalendarView.OnMonthChangeListener {
    private String date;

    @BindView(R.id.iv_calendar)
    ImageView ivCalendar;

    @BindView(R.id.iv_data_second)
    ImageView ivDataSecond;

    @BindView(R.id.iv_data_thirdly)
    ImageView ivDataThirdly;

    @BindView(R.id.iv_first_left)
    ImageView ivFirstLeft;

    @BindView(R.id.iv_first_right)
    ImageView ivFirstRight;

    @BindView(R.id.iv_fourthly_left)
    ImageView ivFourthlyLeft;

    @BindView(R.id.iv_fourthly_right)
    ImageView ivFourthlyRight;

    @BindView(R.id.iv_second_left)
    ImageView ivSecondLeft;

    @BindView(R.id.iv_second_right)
    ImageView ivSecondRight;

    @BindView(R.id.ll_calendar)
    LinearLayout llCalendar;

    @BindView(R.id.ll_data_second)
    LinearLayout llDataSecond;

    @BindView(R.id.ll_data_thirdly)
    LinearLayout llDataThirdly;

    @BindView(R.id.ll_month)
    LinearLayout llMonth;

    @BindView(R.id.ll_data_rem)
    LinearLayout llRem;

    @BindView(R.id.ll_start_button)
    LinearLayout llStartButton;
    private SleepTabFragmentAdapter mAdapter;

    @BindView(R.id.calendarView)
    CalendarView mCalendarView;
    private int mDaySleepDeepSleepTotal;
    private int mDaySleepLightSleepTotal;
    private int mDaySleepRemTotal;
    private int mDaySleepWakeCount;
    private float mMonthSleepAverageDeepSleepTotal;
    private float mMonthSleepAverageLightSleepTotal;
    private float mMonthSleepAverageRemTotal;
    private float mMonthSleepAverageWakeCount;
    private int mMonthSleepDeepSleepTotal;
    private int mMonthSleepLightSleepTotal;

    @BindView(R.id.nsv)
    NestedScrollView mNestedScrollView;

    @BindView(R.id.recycle_view)
    RecyclerView mRecyclerView;
    private List<SleepDb> mSleepDb;
    private SleepHisListAdapter mSleepHisListAdapter;

    @BindView(R.id.stl_tab)
    SlidingTabLayout mSlidingTabLayout;
    private String mToDay;
    private Unbinder mUnbinder;

    @BindView(R.id.vp_tab)
    NoScrollViewPager mViewPager;
    private float mWeekSleepAverageDeepSleepTotal;
    private float mWeekSleepAverageLightSleepTotal;
    private float mWeekSleepAverageRemTotal;
    private float mWeekSleepAverageWakeCount;
    private int monthLastDay;

    @BindView(R.id.rl_analyse)
    RelativeLayout rlAnalyse;

    @BindView(R.id.rl_data_first)
    RelativeLayout rlDataFirst;

    @BindView(R.id.rl_first)
    RelativeLayout rlFirst;

    @BindView(R.id.rl_fourthly)
    RelativeLayout rlFourthly;

    @BindView(R.id.rl_second)
    RelativeLayout rlSecond;

    @BindView(R.id.tv_analyse)
    TextView tvAnalyse;

    @BindView(R.id.tv_analyse_data)
    TextView tvAnalyseData;

    @BindView(R.id.tv_back_today)
    TextView tvBackToday;

    @BindView(R.id.tv_calendar)
    TextView tvCalendar;

    @BindView(R.id.tv_data_first)
    TextView tvDataFirst;

    @BindView(R.id.tv_data_first_unit)
    TextView tvDataFirstUnit;

    @BindView(R.id.tv_data_second)
    TextView tvDataSecond;

    @BindView(R.id.tv_data_second_unit)
    TextView tvDataSecondUnit;

    @BindView(R.id.tv_data_thirdly)
    TextView tvDataThirdly;

    @BindView(R.id.tv_data_thirdly_unit)
    TextView tvDataThirdlyUnit;

    @BindView(R.id.tv_first)
    TextView tvFirst;

    @BindView(R.id.tv_fourthly)
    TextView tvFourthly;

    @BindView(R.id.tv_data_rem)
    TextView tvRem;

    @BindView(R.id.tv_second)
    TextView tvSecond;

    @BindView(R.id.tv_start_button)
    TextView tvStartButton;

    @BindView(R.id.tv_years)
    TextView tvYears;
    private int ARROW = 0;
    private List<String> mTitles = new ArrayList();
    private List<HistorySleepResponse.SleepBean> todayHistorySleepList = new ArrayList();
    private List<HistorySleepResponse.SleepBean> yesterdayHistorySleepList = new ArrayList();
    private List<HistorySleepResponse.SleepBean> mLists = new ArrayList();
    private List<SleepHisListBean> mDaySleepAdapterHisListBean = new ArrayList();
    private List<SleepDayInfo> mDaySleepChartDataBeans = new ArrayList();
    private List<SleepHisListBean> mWeekSleepAdapterHisListBean = new ArrayList();
    private List<SleepHisListBean> mWeekSleepChartDataBeans = new ArrayList();
    private List<SleepHisListBean> mMonthSleepAdapterHisListBean = new ArrayList();
    private List<SleepHisListBean> mMonthSleepChartDataBeans = new ArrayList();
    private boolean isCare = false;

    @Override // com.haibin.calendarview.CalendarView.OnCalendarSelectListener
    public void onCalendarOutOfRange(Calendar calendar) {
    }

    @Override // com.yucheng.smarthealthpro.base.BaseActivity, com.yucheng.smarthealthpro.framework.BaseActivity, androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    protected void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setContentView(R.layout.activity_sleep2);
        this.mUnbinder = ButterKnife.bind(this);
        initView();
        initData();
        getCurrData();
    }

    private void initView() {
        changeTitle(getString(R.string.home_sleep_title));
        showBack();
        showRightImage(R.mipmap.topbar_ic_share, new NavigationBar.MyOnClickListener() { // from class: com.yucheng.smarthealthpro.home.activity.sleep.activity.Sleep2Activity.1
            @Override // com.yucheng.smarthealthpro.framework.view.NavigationBar.MyOnClickListener
            public void onClick(View view) {
                ShareUtils.share(Sleep2Activity.this);
            }
        });
        int statusHeight = AppScreenMgr.getStatusHeight(this.context);
        this.llMonth.setPadding(0, DensityUtils.dip2px(this.context, 50.0f) + statusHeight, 0, 0);
        if (Constant.isTechFeel()) {
            this.rlSecond.setVisibility(8);
        }
        String stringExtra = getIntent().getStringExtra("care");
        if (stringExtra != null && stringExtra.equals(getString(R.string.care_title))) {
            this.isCare = true;
            this.rlFirst.setVisibility(8);
            this.rlSecond.setVisibility(8);
        } else {
            this.tvFirst.setText(getString(R.string.include_bottom_tv_first_button));
            this.tvSecond.setText(getString(R.string.include_bottom_tv_second_button));
        }
        this.tvDataFirstUnit.setText(getString(R.string.home_sleep_waking_unit));
        this.tvDataSecondUnit.setText(getString(R.string.home_sleep_light_sleep_unit));
        this.tvDataThirdlyUnit.setText(getString(R.string.home_sleep_deep_sleep_unit));
        this.llStartButton.setVisibility(8);
        this.tvAnalyse.setText(getString(R.string.home_sleep_analyse_title_tv));
        this.tvFourthly.setText(getString(R.string.include_bottom_tv_fourthly_button));
        this.ivFourthlyRight.setBackground(ResourcesCompat.getDrawable(getResources(), R.mipmap.list_ic_arrow_n, null));
    }

    @Override // com.yucheng.smarthealthpro.base.BaseActivity, com.yucheng.smarthealthpro.framework.BaseActivity, androidx.fragment.app.FragmentActivity, android.app.Activity
    protected void onResume() {
        super.onResume();
    }

    private void initData() {
        this.mToDay = TimeStampUtils.getToDay();
        this.mTitles.add(getString(R.string.date_month_unit));
        this.mTitles.add(getString(R.string.date_week_unit));
        this.mTitles.add(getString(R.string.date_day_unit));
        setRecycleView();
        initViewPager();
        initMonth();
    }

    private void getCurrData() {
        if (this.isCare) {
            ArrayList<String> pastStringArray = YearToDayListUtils.getPastStringArray(this.mToDay, 6);
            ArrayList<String> pastStringArray2 = YearToDayListUtils.getPastStringArray(this.mToDay, 29);
            getNetSleep(pastStringArray.get(0), pastStringArray.get(0), pastStringArray.get(6), 7);
            getNetSleep(pastStringArray2.get(0), pastStringArray2.get(0), pastStringArray2.get(29), 30);
            return;
        }
        new Thread(new Runnable() { // from class: com.yucheng.smarthealthpro.home.activity.sleep.activity.Sleep2Activity.2
            @Override // java.lang.Runnable
            public void run() {
                Sleep2Activity.this.getWeekData();
                Sleep2Activity.this.getMonthData();
            }
        }).start();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void initViewPager() {
        if (isFinishing()) {
            return;
        }
        SleepTabFragmentAdapter sleepTabFragmentAdapter = new SleepTabFragmentAdapter(getSupportFragmentManager(), new SleepTabFragmentAdapter.FragmentCreator() { // from class: com.yucheng.smarthealthpro.home.activity.sleep.activity.Sleep2Activity.3
            @Override // com.yucheng.smarthealthpro.home.activity.sleep.adapter.SleepTabFragmentAdapter.FragmentCreator
            public Fragment createFragment(String str, int i2) {
                return Sleep2TabFragment.newInstance(str.toString(), i2, Sleep2Activity.this.mNestedScrollView, Sleep2Activity.this.monthLastDay, Sleep2Activity.this.mDaySleepChartDataBeans, Sleep2Activity.this.mWeekSleepChartDataBeans, Sleep2Activity.this.mMonthSleepChartDataBeans);
            }

            @Override // com.yucheng.smarthealthpro.home.activity.sleep.adapter.SleepTabFragmentAdapter.FragmentCreator
            public String createTitle(String str) {
                return Html.fromHtml(str).toString();
            }
        });
        this.mAdapter = sleepTabFragmentAdapter;
        this.mViewPager.setAdapter(sleepTabFragmentAdapter);
        this.mAdapter.notifyDataSetChanged();
        this.mViewPager.setOffscreenPageLimit(this.mDaySleepAdapterHisListBean.size() - 1);
        this.mAdapter.setData(this.mTitles);
        this.mSlidingTabLayout.setViewPager(this.mViewPager, (String[]) this.mTitles.toArray(new String[0]));
        this.mSlidingTabLayout.setCurrentTab(2, true);
        this.mViewPager.addOnPageChangeListener(new OnPageChangeListenerImpl());
    }

    private class OnPageChangeListenerImpl implements ViewPager.OnPageChangeListener {
        @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
        public void onPageScrollStateChanged(int i2) {
        }

        @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
        public void onPageScrolled(int i2, float f2, int i3) {
        }

        private OnPageChangeListenerImpl() {
        }

        @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
        public void onPageSelected(int i2) {
            Sleep2Activity.this.mViewPager.setCurrentItem(i2);
            if (i2 == 0) {
                Sleep2Activity.this.freshMonthData();
            } else if (i2 == 1) {
                Sleep2Activity.this.freshWeekData();
            } else {
                if (i2 != 2) {
                    return;
                }
                Sleep2Activity.this.freshDayData();
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void freshDayData() {
        this.tvBackToday.setVisibility(8);
        this.llCalendar.setVisibility(0);
        if (this.mDaySleepDeepSleepTotal != 0 || this.mDaySleepLightSleepTotal != 0) {
            this.tvDataFirst.setText(this.mDaySleepWakeCount + "");
            this.tvDataSecond.setText(parseTime(this.mDaySleepLightSleepTotal));
            this.tvDataThirdly.setText(parseTime(this.mDaySleepDeepSleepTotal));
            this.tvRem.setText(parseTime(this.mDaySleepRemTotal));
            dataAnalysis((this.mDaySleepDeepSleepTotal + this.mDaySleepLightSleepTotal) / 3600.0f);
        } else {
            this.tvDataFirst.setText(HelpFormatter.DEFAULT_LONG_OPT_PREFIX);
            this.tvDataSecond.setText(HelpFormatter.DEFAULT_LONG_OPT_PREFIX);
            this.tvDataThirdly.setText(HelpFormatter.DEFAULT_LONG_OPT_PREFIX);
            this.tvRem.setText(HelpFormatter.DEFAULT_LONG_OPT_PREFIX);
            this.mDaySleepDeepSleepTotal = 0;
            this.mDaySleepLightSleepTotal = 0;
            dataAnalysis(0.0f);
        }
        this.mSleepHisListAdapter.setList(this.mDaySleepAdapterHisListBean);
        this.mSleepHisListAdapter.notifyDataSetChanged();
        this.tvDataFirstUnit.setText(getString(R.string.sleep_waking_unit));
        this.tvDataSecondUnit.setText(getString(R.string.light_sleep));
        this.tvDataThirdlyUnit.setText(getString(R.string.deep_sleep));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void freshWeekData() {
        this.tvBackToday.setVisibility(0);
        this.llCalendar.setVisibility(8);
        List<SleepHisListBean> list = this.mWeekSleepAdapterHisListBean;
        if (list != null && list.size() > 0) {
            this.tvDataFirst.setText(String.format("%.2f", Float.valueOf(this.mWeekSleepAverageWakeCount)));
            this.tvDataSecond.setText(parseTime((int) this.mWeekSleepAverageLightSleepTotal));
            this.tvDataThirdly.setText(parseTime((int) this.mWeekSleepAverageDeepSleepTotal));
            this.tvRem.setText(parseTime((int) this.mWeekSleepAverageRemTotal));
            dataAnalysis((this.mWeekSleepAverageLightSleepTotal + this.mWeekSleepAverageDeepSleepTotal) / 3600.0f);
        } else {
            this.tvDataFirst.setText(HelpFormatter.DEFAULT_LONG_OPT_PREFIX);
            this.tvDataSecond.setText(HelpFormatter.DEFAULT_LONG_OPT_PREFIX);
            this.tvDataThirdly.setText(HelpFormatter.DEFAULT_LONG_OPT_PREFIX);
            this.tvRem.setText(HelpFormatter.DEFAULT_LONG_OPT_PREFIX);
            this.mWeekSleepAverageLightSleepTotal = 0.0f;
            this.mWeekSleepAverageDeepSleepTotal = 0.0f;
            dataAnalysis(0.0f);
        }
        this.mSleepHisListAdapter.setList(this.mWeekSleepAdapterHisListBean);
        this.mSleepHisListAdapter.notifyDataSetChanged();
        this.tvDataFirstUnit.setText(getString(R.string.home_sleep_waking_unit));
        this.tvDataSecondUnit.setText(getString(R.string.home_sleep_light_sleep_unit));
        this.tvDataThirdlyUnit.setText(getString(R.string.home_sleep_deep_sleep_unit));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void freshMonthData() {
        this.tvBackToday.setVisibility(0);
        this.llCalendar.setVisibility(8);
        List<SleepHisListBean> list = this.mMonthSleepAdapterHisListBean;
        if (list != null && list.size() > 0) {
            this.tvDataFirst.setText(String.format("%.2f", Float.valueOf(this.mMonthSleepAverageWakeCount)));
            this.tvDataSecond.setText(parseTime((int) this.mMonthSleepAverageLightSleepTotal));
            this.tvDataThirdly.setText(parseTime((int) this.mMonthSleepAverageDeepSleepTotal));
            this.tvRem.setText(parseTime((int) this.mMonthSleepAverageRemTotal));
            dataAnalysis((this.mMonthSleepAverageLightSleepTotal + this.mMonthSleepAverageDeepSleepTotal) / 3600.0f);
        } else {
            this.tvDataFirst.setText(HelpFormatter.DEFAULT_LONG_OPT_PREFIX);
            this.tvDataSecond.setText(HelpFormatter.DEFAULT_LONG_OPT_PREFIX);
            this.tvDataThirdly.setText(HelpFormatter.DEFAULT_LONG_OPT_PREFIX);
            this.tvRem.setText(HelpFormatter.DEFAULT_LONG_OPT_PREFIX);
            this.mMonthSleepAverageLightSleepTotal = 0.0f;
            this.mMonthSleepAverageDeepSleepTotal = 0.0f;
            dataAnalysis(0.0f);
        }
        this.mSleepHisListAdapter.setList(this.mMonthSleepAdapterHisListBean);
        this.mSleepHisListAdapter.notifyDataSetChanged();
        this.tvDataFirstUnit.setText(getString(R.string.home_sleep_waking_unit));
        this.tvDataSecondUnit.setText(getString(R.string.home_sleep_light_sleep_unit));
        this.tvDataThirdlyUnit.setText(getString(R.string.home_sleep_deep_sleep_unit));
    }

    public void dataAnalysis(float f2) {
        if (f2 > 10.0f) {
            this.tvAnalyseData.setText(getText(R.string.home_sleep_analyse_too_much_sleep));
            return;
        }
        if (f2 > 4.0f) {
            this.tvAnalyseData.setText(getText(R.string.home_sleep_analyse_normal));
        } else if (f2 > 0.0f) {
            this.tvAnalyseData.setText(getText(R.string.home_sleep_analyse_sleep_debt));
        } else {
            this.tvAnalyseData.setText("");
        }
    }

    private void setRecycleView() {
        this.mRecyclerView.setLayoutManager(new LinearLayoutManager(this));
        SleepHisListAdapter sleepHisListAdapter = new SleepHisListAdapter(R.layout.item_sleep_his_list);
        this.mSleepHisListAdapter = sleepHisListAdapter;
        sleepHisListAdapter.addData((Collection) this.mDaySleepAdapterHisListBean);
        this.mRecyclerView.setAdapter(this.mSleepHisListAdapter);
        this.mRecyclerView.setNestedScrollingEnabled(false);
    }

    private void initMonth() {
        this.mCalendarView.setOnCalendarSelectListener(this);
        this.mCalendarView.setOnMonthChangeListener(this);
        this.mCalendarView.scrollToCurrent();
        this.mCalendarView.setOnCalendarInterceptListener(new CalendarView.OnCalendarInterceptListener() { // from class: com.yucheng.smarthealthpro.home.activity.sleep.activity.Sleep2Activity.4
            @Override // com.haibin.calendarview.CalendarView.OnCalendarInterceptListener
            public void onCalendarInterceptClick(Calendar calendar, boolean z) {
            }

            @Override // com.haibin.calendarview.CalendarView.OnCalendarInterceptListener
            public boolean onCalendarIntercept(Calendar calendar) {
                return !YearToDayListUtils.isMidDate(YearToDayListUtils.getPastDate(30, new Date()), new StringBuilder().append(calendar.getYear()).append(HelpFormatter.DEFAULT_OPT_PREFIX).append(String.format(TimeModel.ZERO_LEADING_NUMBER_FORMAT, Integer.valueOf(calendar.getMonth()))).append(HelpFormatter.DEFAULT_OPT_PREFIX).append(String.format(TimeModel.ZERO_LEADING_NUMBER_FORMAT, Integer.valueOf(calendar.getDay()))).toString(), new Date());
            }
        });
        if (Constant.isTechFeel()) {
            this.tvYears.setText(String.format(TimeModel.ZERO_LEADING_NUMBER_FORMAT, Integer.valueOf(this.mCalendarView.getCurMonth())) + "/" + this.mCalendarView.getCurYear());
        } else {
            this.tvYears.setText(this.mCalendarView.getCurYear() + "/" + String.format(TimeModel.ZERO_LEADING_NUMBER_FORMAT, Integer.valueOf(this.mCalendarView.getCurMonth())));
        }
    }

    @Override // com.haibin.calendarview.CalendarView.OnCalendarSelectListener
    public void onCalendarSelect(Calendar calendar, boolean z) {
        this.monthLastDay = YearToDayListUtils.getMonthLastDay(calendar.getYear(), calendar.getMonth());
        this.date = TimeDateUtil.intToStr(calendar.getYear(), calendar.getMonth(), calendar.getDay());
        initDayData();
        if (this.isCare) {
            this.mLists.clear();
            this.todayHistorySleepList.clear();
            this.yesterdayHistorySleepList.clear();
            getDaySleep(this.date, 0);
        } else {
            getThatVeryDayData(this.date);
        }
        this.tvCalendar.setText(calendar.getMonth() + "/" + calendar.getDay());
        this.llMonth.setVisibility(8);
    }

    @Override // com.haibin.calendarview.CalendarView.OnMonthChangeListener
    public void onMonthChange(int i2, int i3) {
        if (Constant.isTechFeel()) {
            this.tvYears.setText(String.format(TimeModel.ZERO_LEADING_NUMBER_FORMAT, Integer.valueOf(i3)) + "/" + i2);
        } else {
            this.tvYears.setText(i2 + "/" + String.format(TimeModel.ZERO_LEADING_NUMBER_FORMAT, Integer.valueOf(i3)));
        }
    }

    public void getThatVeryDayData(String str) {
        getDaySleepData(str, 1);
        getDaySleepData(str, 0);
        if (this.mDaySleepAdapterHisListBean.size() > 0 && this.mDaySleepAdapterHisListBean.get(0).getDeepSleepCount() == 65535) {
            this.llRem.setVisibility(0);
            this.mDaySleepWakeCount = (this.mDaySleepWakeCount + this.mDaySleepAdapterHisListBean.size()) - 1;
        } else {
            this.llRem.setVisibility(8);
            if (this.mDaySleepWakeCount > 0 && Constant.isBNRHealth()) {
                this.mDaySleepWakeCount--;
            }
        }
        initViewPager();
        Collections.reverse(this.mDaySleepAdapterHisListBean);
        this.mSleepHisListAdapter.setList(this.mDaySleepAdapterHisListBean);
        this.mSleepHisListAdapter.notifyDataSetChanged();
    }

    private void initDayData() {
        this.mDaySleepAdapterHisListBean.clear();
        this.mDaySleepChartDataBeans.clear();
        this.mDaySleepWakeCount = 0;
        this.mDaySleepDeepSleepTotal = 0;
        this.mDaySleepLightSleepTotal = 0;
        this.mDaySleepRemTotal = 0;
    }

    private void getDaySleepData(String str, int i2) {
        int i3 = i2;
        try {
            String pastDateString = YearToDayListUtils.getPastDateString(i3, new SimpleDateFormat(AppDateMgr.DF_YYYY_MM_DD).parse(str));
            List<SleepDb> queryIdYearToDay = new SleepDbUtils(this).queryIdYearToDay(pastDateString);
            this.mSleepDb = queryIdYearToDay;
            if (queryIdYearToDay != null) {
                Logger.d("chong-------mSleepDb==" + this.mSleepDb.size());
                int i4 = 0;
                while (i4 < this.mSleepDb.size()) {
                    SleepDb sleepDb = this.mSleepDb.get(i4);
                    if (TimeStampUtils.dateForStringYearToDate(TimeStampUtils.longStampForDate(sleepDb.getStartTime())).equals(pastDateString)) {
                        int parseInt = Integer.parseInt(TimeStampUtils.dateForStringToHourDate(TimeStampUtils.longStampForDate(sleepDb.getStartTime())));
                        int parseInt2 = Integer.parseInt(TimeStampUtils.dateForStringToHourDate(TimeStampUtils.longStampForDate(sleepDb.getEndTime())));
                        Logger.d("chong---------startTime==" + sleepDb.getStartTime());
                        if ((parseInt >= 20 && i3 == 1) || (parseInt <= 8 && i3 == 0 && parseInt2 <= 12)) {
                            if (sleepDb.getDeepSleepCount() == 65535) {
                                this.mDaySleepWakeCount += sleepDb.wakeCount;
                            } else {
                                this.mDaySleepWakeCount++;
                            }
                            this.mDaySleepDeepSleepTotal += sleepDb.getDeepSleepTotal();
                            this.mDaySleepLightSleepTotal += sleepDb.getLightSleepTotal();
                            this.mDaySleepRemTotal += sleepDb.getRapidEyeMovementTotal();
                            this.mDaySleepAdapterHisListBean.add(new SleepHisListBean(sleepDb.getStartTime(), sleepDb.getEndTime(), sleepDb.getDeepSleepTotal() + sleepDb.getLightSleepTotal() + sleepDb.getRapidEyeMovementTotal(), sleepDb.getDeepSleepTotal(), sleepDb.getLightSleepTotal(), sleepDb.getDeepSleepCount(), sleepDb.getLightSleepCount(), sleepDb.getWakeCount(), "", sleepDb.getRapidEyeMovementTotal(), sleepDb.getWakeDuration(), false));
                            setDayCharData(sleepDb.getSleepData());
                        }
                    }
                    i4++;
                    i3 = i2;
                }
            }
        } catch (Exception e2) {
            e2.printStackTrace();
        }
    }

    /*  JADX ERROR: NullPointerException in pass: LoopRegionVisitor
        java.lang.NullPointerException: Cannot invoke "jadx.core.dex.instructions.args.SSAVar.use(jadx.core.dex.instructions.args.RegisterArg)" because "ssaVar" is null
        	at jadx.core.dex.nodes.InsnNode.rebindArgs(InsnNode.java:493)
        	at jadx.core.dex.nodes.InsnNode.rebindArgs(InsnNode.java:496)
        */
    private void setDayCharData(java.lang.String r15) {
        /*
            Method dump skipped, instructions count: 306
            To view this dump change 'Code comments level' option to 'DEBUG'
        */
        throw new UnsupportedOperationException("Method not decompiled: com.yucheng.smarthealthpro.home.activity.sleep.activity.Sleep2Activity.setDayCharData(java.lang.String):void");
    }

    public void getWeekData() {
        this.mWeekSleepAdapterHisListBean.clear();
        this.mWeekSleepChartDataBeans.clear();
        this.mWeekSleepAverageDeepSleepTotal = 0.0f;
        this.mWeekSleepAverageLightSleepTotal = 0.0f;
        this.mWeekSleepAverageRemTotal = 0.0f;
        this.mWeekSleepAverageWakeCount = 0.0f;
        getDataByDays(7);
    }

    private void getDataByDays(int i2) {
        long j2;
        long j3;
        int i3;
        int i4;
        int i5;
        int i6;
        int i7;
        int i8;
        int i9;
        int i10 = i2;
        ArrayList<String> pastStringArray = YearToDayListUtils.getPastStringArray(this.mToDay, i10);
        int i11 = 1;
        int i12 = 0;
        int i13 = 0;
        int i14 = 0;
        int i15 = 0;
        while (i11 <= i10) {
            List<SleepDb> queryEqTimeYearToDay = new SleepDbUtils(this).queryEqTimeYearToDay(pastStringArray.get(i11));
            this.mSleepDb = queryEqTimeYearToDay;
            int i16 = i11 - 1;
            queryEqTimeYearToDay.addAll(new SleepDbUtils(this).queryEqTimeYearToDay(pastStringArray.get(i16)));
            if (this.mSleepDb != null) {
                i6 = 0;
                int i17 = 0;
                int i18 = 0;
                int i19 = 0;
                j2 = 0;
                j3 = 0;
                i7 = 0;
                i8 = 0;
                for (int i20 = 0; i20 < this.mSleepDb.size(); i20++) {
                    SleepDb sleepDb = this.mSleepDb.get(i20);
                    int deepSleepTotal = sleepDb.getDeepSleepTotal();
                    int lightSleepTotal = sleepDb.getLightSleepTotal();
                    int i21 = sleepDb.rapidEyeMovementTotal;
                    int i22 = sleepDb.wakeCount;
                    int hourFromTimeStamp = YearToDayListUtils.getHourFromTimeStamp(sleepDb.getStartTime());
                    if ((hourFromTimeStamp <= 12 || !sleepDb.getTimeYearToDate().equals(pastStringArray.get(i11))) && ((hourFromTimeStamp >= 20 || !sleepDb.getTimeYearToDate().equals(pastStringArray.get(i16))) && (i20 <= 0 || sleepDb.getStartTime() <= this.mSleepDb.get(i20 - 1).getEndTime()))) {
                        if (sleepDb.getDeepSleepCount() != 65535) {
                            i22++;
                            i7 += sleepDb.getDeepSleepCount();
                            i8 += sleepDb.getLightSleepCount();
                        }
                        if (i20 == 0 || j2 == 0) {
                            j2 = sleepDb.getStartTime();
                        }
                        if (i20 == this.mSleepDb.size() - 1 || j3 == 0) {
                            j3 = sleepDb.getEndTime();
                        }
                        i6 += deepSleepTotal;
                        i17 += lightSleepTotal;
                        i18 += i21;
                        i19 += i22;
                    }
                }
                i3 = i17;
                i5 = i18;
                i4 = i19;
            } else {
                j2 = 0;
                j3 = 0;
                i3 = 0;
                i4 = 0;
                i5 = 0;
                i6 = 0;
                i7 = 0;
                i8 = 0;
            }
            if (i3 != 0) {
                i14 += i6;
                i12 += i3;
                i15 += i5;
                i13 += i4;
                i9 = i2;
                if (i9 == 7) {
                    long j4 = i6 + i3 + i5;
                    long j5 = j2;
                    long j6 = j3;
                    int i23 = i6;
                    int i24 = i3;
                    int i25 = i7;
                    int i26 = i8;
                    int i27 = i4;
                    int i28 = i5;
                    this.mWeekSleepAdapterHisListBean.add(new SleepHisListBean(j5, j6, j4, i23, i24, i25, i26, i27, "正常", i28, 0, true));
                    this.mWeekSleepChartDataBeans.add(new SleepHisListBean(j5, j6, j4, i23, i24, i25, i26, i27, "正常", i28, 0, true));
                } else if (i9 == 30) {
                    long j7 = i6 + i3 + i5;
                    this.mMonthSleepAdapterHisListBean.add(new SleepHisListBean(j2, j3, j7, i6, i3, i7, i8, i4, "正常", i5, 0, true));
                    this.mMonthSleepChartDataBeans.add(new SleepHisListBean(j2, j3, j7, i6, i3, i7, i8, i4, "正常", i5, 0, true));
                }
            } else {
                i9 = i2;
                if (i9 == 7) {
                    this.mWeekSleepChartDataBeans.add(new SleepHisListBean(j2, j3, i6 + i3 + i5, i6, i3, i7, i8, i4, "正常", i5, 0, true));
                } else if (i9 == 30) {
                    this.mMonthSleepChartDataBeans.add(new SleepHisListBean(j2, j3, i6 + i3 + i5, i6, i3, i7, i8, i4, "正常", i5, 0, true));
                }
            }
            i11++;
            i10 = i9;
        }
        int i29 = i10;
        if (i12 != 0) {
            if (i29 == 7) {
                Collections.reverse(this.mWeekSleepAdapterHisListBean);
                this.mWeekSleepAverageWakeCount = FormatUtil.getBigDecimal((i13 * 1.0f) / this.mWeekSleepAdapterHisListBean.size()).setScale(1, 4).floatValue();
                this.mWeekSleepAverageLightSleepTotal = FormatUtil.getBigDecimal((i12 * 1.0f) / this.mWeekSleepAdapterHisListBean.size()).setScale(1, 4).floatValue();
                this.mWeekSleepAverageDeepSleepTotal = FormatUtil.getBigDecimal((i14 * 1.0f) / this.mWeekSleepAdapterHisListBean.size()).setScale(1, 4).floatValue();
                this.mWeekSleepAverageRemTotal = FormatUtil.getBigDecimal((i15 * 1.0f) / this.mWeekSleepAdapterHisListBean.size()).setScale(1, 4).floatValue();
                return;
            }
            if (i29 == 30) {
                Collections.reverse(this.mMonthSleepAdapterHisListBean);
                this.mMonthSleepAverageWakeCount = FormatUtil.getBigDecimal((i13 * 1.0f) / this.mMonthSleepAdapterHisListBean.size()).setScale(1, 4).floatValue();
                this.mMonthSleepAverageLightSleepTotal = FormatUtil.getBigDecimal((i12 * 1.0f) / this.mMonthSleepAdapterHisListBean.size()).setScale(1, 4).floatValue();
                this.mMonthSleepAverageDeepSleepTotal = FormatUtil.getBigDecimal((i14 * 1.0f) / this.mMonthSleepAdapterHisListBean.size()).setScale(1, 4).floatValue();
                this.mMonthSleepAverageRemTotal = FormatUtil.getBigDecimal((i15 * 1.0f) / this.mMonthSleepAdapterHisListBean.size()).setScale(1, 4).floatValue();
            }
        }
    }

    public void getMonthData() {
        this.mMonthSleepAdapterHisListBean.clear();
        this.mMonthSleepChartDataBeans.clear();
        this.mMonthSleepAverageDeepSleepTotal = 0.0f;
        this.mMonthSleepAverageLightSleepTotal = 0.0f;
        this.mMonthSleepAverageRemTotal = 0.0f;
        this.mMonthSleepAverageWakeCount = 0.0f;
        getDataByDays(30);
        runOnUiThread(new Runnable() { // from class: com.yucheng.smarthealthpro.home.activity.sleep.activity.Sleep2Activity.6
            @Override // java.lang.Runnable
            public void run() {
                Sleep2Activity.this.initViewPager();
            }
        });
    }

    public void getDaySleep(final String str, final int i2) {
        HashMap hashMap = new HashMap();
        hashMap.put("userId", getIntent().getExtras().getString(Constant.SpConstKey.DEV_ID));
        hashMap.put("day", str);
        HttpUtils.getInstance().postMsgAsynHttp(this, Constants.sleepDayUrl, hashMap, new HttpUtils.HttpCallback() { // from class: com.yucheng.smarthealthpro.home.activity.sleep.activity.Sleep2Activity.7
            @Override // com.yucheng.smarthealthpro.framework.http.HttpUtils.HttpCallback
            public void onSuccess(String str2) {
                if (str2 != null) {
                    try {
                        HistorySleepResponse historySleepResponse = (HistorySleepResponse) new Gson().fromJson(str2, HistorySleepResponse.class);
                        if (historySleepResponse != null) {
                            List<HistorySleepResponse.SleepBean> list = historySleepResponse.data;
                            if (list != null && list.size() > 0) {
                                Sleep2Activity.this.mLists.addAll(Tools.sortListSleep(list));
                            }
                            if (i2 == 0) {
                                Sleep2Activity.this.getDaySleep(YearToDayListUtils.getPastDateString(1, new SimpleDateFormat(AppDateMgr.DF_YYYY_MM_DD).parse(str)), 1);
                                return;
                            }
                            Sleep2Activity sleep2Activity = Sleep2Activity.this;
                            sleep2Activity.mLists = Tools.removeSleepDuplicate(sleep2Activity.GetFixedDataOfSleep(sleep2Activity.mLists, Sleep2Activity.this.date));
                            Sleep2Activity.this.setDayData();
                        }
                    } catch (Exception e2) {
                        e2.printStackTrace();
                    }
                }
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void setDayData() {
        for (HistorySleepResponse.SleepBean sleepBean : this.mLists) {
            setDayCharData(sleepBean.mlist);
            this.mDaySleepDeepSleepTotal += sleepBean.dsTimes;
            this.mDaySleepLightSleepTotal += sleepBean.qsTimes;
            this.mDaySleepRemTotal += sleepBean.remTimes;
            if (sleepBean.dsCount == 65535) {
                try {
                    int parseInt = this.mDaySleepWakeCount + Integer.parseInt(sleepBean.wakeCount.isEmpty() ? "0" : sleepBean.wakeCount);
                    this.mDaySleepWakeCount = parseInt;
                    if (parseInt == 0) {
                        this.mDaySleepWakeCount = this.mLists.size() - 1;
                    }
                } catch (NumberFormatException e2) {
                    e2.printStackTrace();
                }
            } else {
                this.mDaySleepWakeCount = this.mLists.size();
                if (Constant.isBNRHealth() && this.mLists.size() > 0) {
                    this.mDaySleepWakeCount--;
                }
                this.llRem.setVisibility(8);
            }
            this.mDaySleepAdapterHisListBean.add(new SleepHisListBean(TimeStampUtils.getStringToTimestamp(sleepBean.beginTime, "yyyy-MM-dd HH:mm:ss").longValue(), TimeStampUtils.getStringToTimestamp(sleepBean.endTime, "yyyy-MM-dd HH:mm:ss").longValue(), sleepBean.dsTimes + sleepBean.qsTimes + sleepBean.remTimes, sleepBean.dsTimes, sleepBean.qsTimes, sleepBean.dsCount, sleepBean.qsCount, this.mLists.size(), "", sleepBean.remTimes, 0, false));
        }
        if (this.mLists.size() > 0 && this.mLists.get(0).dsCount == 65535) {
            this.mDaySleepWakeCount = (this.mDaySleepWakeCount + this.mLists.size()) - 1;
        }
        initViewPager();
        Collections.reverse(this.mDaySleepAdapterHisListBean);
        this.mSleepHisListAdapter.setList(this.mDaySleepAdapterHisListBean);
        this.mSleepHisListAdapter.notifyDataSetChanged();
    }

    public List<HistorySleepResponse.SleepBean> GetFixedDataOfSleep(List<HistorySleepResponse.SleepBean> list, String str) {
        ArrayList arrayList = new ArrayList();
        if (list != null && list.size() > 0) {
            int size = list.size();
            long stringToDate = TimeStampUtils.getStringToDate(str, AppDateMgr.DF_YYYY_MM_DD);
            long j2 = stringToDate - 14400000;
            long j3 = stringToDate + 28800000;
            for (int i2 = 0; i2 < size; i2++) {
                if (Tools.getTime(list.get(i2).beginTime) >= j2 && Tools.getTime(list.get(i2).beginTime) <= j3) {
                    arrayList.add(list.get(i2));
                }
            }
        }
        return arrayList;
    }

    private void getNetSleep(String str, String str2, String str3, final int i2) {
        HashMap hashMap = new HashMap();
        hashMap.put("userId", getIntent().getExtras().getString(Constant.SpConstKey.DEV_ID));
        hashMap.put("day", str);
        hashMap.put("startDate", str2);
        hashMap.put("endDate", str3);
        hashMap.put("type", "1");
        HttpUtils.getInstance().postMsgAsynHttp(this, Constants.sleepDayUrl, hashMap, new HttpUtils.HttpCallback() { // from class: com.yucheng.smarthealthpro.home.activity.sleep.activity.Sleep2Activity.8
            @Override // com.yucheng.smarthealthpro.framework.http.HttpUtils.HttpCallback
            public void onSuccess(String str4) {
                if (str4 != null) {
                    Sleep2Activity.this.parseSleepData(str4, i2);
                }
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void parseSleepData(String str, int i2) {
        CareSleepWeekMonthBean careSleepWeekMonthBean;
        try {
            careSleepWeekMonthBean = (CareSleepWeekMonthBean) new Gson().fromJson(str, CareSleepWeekMonthBean.class);
        } catch (JsonSyntaxException e2) {
            e2.printStackTrace();
            careSleepWeekMonthBean = null;
        }
        if (careSleepWeekMonthBean == null || careSleepWeekMonthBean.data == null) {
            return;
        }
        List<CareSleepWeekMonthBean.DataBean> sortWeekAndMonthListSleep = Tools.sortWeekAndMonthListSleep(careSleepWeekMonthBean.data);
        ArrayList arrayList = new ArrayList();
        ArrayList arrayList2 = new ArrayList();
        int i3 = 0;
        int i4 = 0;
        int i5 = 0;
        int i6 = 0;
        int i7 = 0;
        while (i3 < sortWeekAndMonthListSleep.size()) {
            CareSleepWeekMonthBean.DataBean dataBean = sortWeekAndMonthListSleep.get(i3);
            int i8 = i4 + dataBean.dsStatistics;
            int i9 = i5 + dataBean.qsStatistics;
            i6 += dataBean.remTotalDuration;
            i7 += dataBean.count;
            arrayList.add(new SleepHisListBean(TimeStampUtils.getStringToDate(dataBean.dateformat, AppDateMgr.DF_YYYY_MM_DD), 0L, dataBean.dsStatistics + dataBean.qsStatistics + dataBean.remTotalDuration, dataBean.dsStatistics, dataBean.qsStatistics, 0, 0, dataBean.count, "正常", dataBean.remTotalDuration, 0, true));
            i3++;
            i4 = i8;
            i5 = i9;
        }
        ArrayList<String> pastStringArray = YearToDayListUtils.getPastStringArray(this.mToDay, i2 - 1);
        for (int i10 = 0; i10 < pastStringArray.size(); i10++) {
            arrayList2.add(new SleepHisListBean(0L, 0L, 0L, 0, 0, 0, 0, 0, "正常", 0, 0, true));
        }
        for (int i11 = 0; i11 < pastStringArray.size(); i11++) {
            int i12 = 0;
            while (true) {
                if (i12 < sortWeekAndMonthListSleep.size()) {
                    CareSleepWeekMonthBean.DataBean dataBean2 = sortWeekAndMonthListSleep.get(i12);
                    if (dataBean2.dateformat.equals(pastStringArray.get(i11))) {
                        arrayList2.remove(i11);
                        arrayList2.add(i11, new SleepHisListBean(TimeStampUtils.getStringToDate(dataBean2.dateformat, AppDateMgr.DF_YYYY_MM_DD), 0L, 0L, dataBean2.dsStatistics, dataBean2.qsStatistics, 0, 0, 0, "正常", dataBean2.remTotalDuration, 0, true));
                        break;
                    }
                    i12++;
                }
            }
        }
        if (sortWeekAndMonthListSleep.size() == 0) {
            return;
        }
        if (i2 == 7) {
            this.mWeekSleepAverageDeepSleepTotal = i4 / sortWeekAndMonthListSleep.size();
            this.mWeekSleepAverageLightSleepTotal = i5 / sortWeekAndMonthListSleep.size();
            this.mWeekSleepAverageWakeCount = i7 / sortWeekAndMonthListSleep.size();
            this.mWeekSleepAverageRemTotal = i6 / sortWeekAndMonthListSleep.size();
            this.mWeekSleepAdapterHisListBean = arrayList;
            this.mWeekSleepChartDataBeans = arrayList2;
            return;
        }
        if (i2 == 30) {
            this.mMonthSleepAverageDeepSleepTotal = i4 / sortWeekAndMonthListSleep.size();
            this.mMonthSleepAverageLightSleepTotal = i5 / sortWeekAndMonthListSleep.size();
            this.mMonthSleepAverageWakeCount = i7 / sortWeekAndMonthListSleep.size();
            this.mMonthSleepAverageRemTotal = i6 / sortWeekAndMonthListSleep.size();
            this.mMonthSleepAdapterHisListBean = arrayList;
            this.mMonthSleepChartDataBeans = arrayList2;
        }
    }

    @OnClick({R.id.ll_calendar, R.id.tv_back_today, R.id.rl_first, R.id.rl_second, R.id.rl_fourthly, R.id.ll_month})
    public void onViewClicked(View view) {
        switch (view.getId()) {
            case R.id.ll_calendar /* 2131296914 */:
                this.llMonth.setVisibility(0);
                break;
            case R.id.ll_month /* 2131296943 */:
                this.llMonth.setVisibility(8);
                break;
            case R.id.rl_first /* 2131297288 */:
                startActivity(new Intent(this.context, (Class<?>) MeHealthSettingActivity.class));
                break;
            case R.id.rl_fourthly /* 2131297289 */:
                if (this.ARROW == 0) {
                    this.mRecyclerView.setVisibility(0);
                    this.ivFourthlyRight.setBackground(ResourcesCompat.getDrawable(getResources(), R.mipmap.list_ic_arrow_s, null));
                    this.ARROW = 1;
                    this.mNestedScrollView.postDelayed(new Runnable() { // from class: com.yucheng.smarthealthpro.home.activity.sleep.activity.Sleep2Activity.9
                        @Override // java.lang.Runnable
                        public void run() {
                            Sleep2Activity.this.mNestedScrollView.smoothScrollTo(0, (int) (Sleep2Activity.this.mNestedScrollView.getScrollY() + (DpUtil.dp2px(Sleep2Activity.this.context, 56.0f) * 1.5f)));
                        }
                    }, 100L);
                    break;
                } else {
                    this.mRecyclerView.setVisibility(8);
                    this.ivFourthlyRight.setBackground(ResourcesCompat.getDrawable(getResources(), R.mipmap.list_ic_arrow_n, null));
                    this.ARROW = 0;
                    break;
                }
            case R.id.rl_second /* 2131297312 */:
                startActivity(new Intent(this.context, (Class<?>) HealthyActivity.class));
                break;
            case R.id.tv_back_today /* 2131297580 */:
                this.mCalendarView.scrollToCurrent();
                break;
        }
    }

    @Override // androidx.appcompat.app.AppCompatActivity, android.app.Activity, android.view.ContextThemeWrapper, android.content.ContextWrapper
    protected void attachBaseContext(Context context) {
        super.attachBaseContext(ViewPumpContextWrapper.wrap(context));
    }

    @Override // com.yucheng.smarthealthpro.base.BaseActivity, com.yucheng.smarthealthpro.framework.BaseActivity, androidx.appcompat.app.AppCompatActivity, androidx.fragment.app.FragmentActivity, android.app.Activity
    protected void onDestroy() {
        super.onDestroy();
        Unbinder unbinder = this.mUnbinder;
        if (unbinder != null) {
            unbinder.unbind();
        }
    }

    public SpannableString parseTime(int i2) {
        int i3 = i2 - (i2 % 60);
        int i4 = (i3 / 60) % 60;
        return setSpaning(String.format("%d h %d min", Integer.valueOf((i3 - (i4 * 60)) / 3600), Integer.valueOf(i4)));
    }

    private SpannableString setSpaning(String str) {
        SpannableString spannableString = new SpannableString(str);
        int lastIndexOf = spannableString.toString().lastIndexOf(" h ");
        int lastIndexOf2 = spannableString.toString().lastIndexOf(" min");
        if (lastIndexOf != -1) {
            ForegroundColorSpan foregroundColorSpan = new ForegroundColorSpan(Color.parseColor("#808080"));
            AbsoluteSizeSpan absoluteSizeSpan = new AbsoluteSizeSpan(14, true);
            int i2 = lastIndexOf + 3;
            spannableString.setSpan(foregroundColorSpan, lastIndexOf, i2, 17);
            spannableString.setSpan(absoluteSizeSpan, lastIndexOf, i2, 17);
        }
        if (lastIndexOf2 != -1) {
            ForegroundColorSpan foregroundColorSpan2 = new ForegroundColorSpan(Color.parseColor("#808080"));
            AbsoluteSizeSpan absoluteSizeSpan2 = new AbsoluteSizeSpan(14, true);
            int i3 = lastIndexOf2 + 4;
            spannableString.setSpan(foregroundColorSpan2, lastIndexOf2, i3, 17);
            spannableString.setSpan(absoluteSizeSpan2, lastIndexOf2, i3, 17);
        }
        return spannableString;
    }
}
