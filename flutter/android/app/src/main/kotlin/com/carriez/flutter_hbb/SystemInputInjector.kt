package com.carriez.flutter_hbb

import android.content.Context
import android.content.pm.PackageManager
import android.hardware.input.InputManager
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.util.Log
import android.view.InputDevice
import android.view.InputEvent
import android.view.KeyCharacterMap
import android.view.KeyEvent as KeyEventAndroid
import android.view.MotionEvent
import android.view.ViewConfiguration
import androidx.core.content.ContextCompat
import hbb.MessageOuterClass.KeyEvent
import hbb.KeyEventConverter
import java.lang.Character
import kotlin.math.max

object SystemInputInjector {
    private const val logTag = "SystemInputInjector"
    private const val injectPermission = "android.permission.INJECT_EVENTS"

    private val handler = Handler(Looper.getMainLooper())
    private val longPressDuration =
        ViewConfiguration.getTapTimeout().toLong() + ViewConfiguration.getLongPressTimeout().toLong()

    private var mouseX = 0f
    private var mouseY = 0f
    private var mouseDown = false
    private var mouseDownTime = 0L

    private var touchX = 0f
    private var touchY = 0f
    private var touchDown = false
    private var touchDownTime = 0L

    private var recentActionRunnable: Runnable? = null

    fun tryInjectPointer(context: Context, kind: Int, mask: Int, x: Int, y: Int): Boolean {
        if (!hasInjectPermission(context)) {
            return false
        }
        return when (kind) {
            0 -> injectTouch(context, mask, x, y)
            1 -> injectMouse(context, mask, x, y)
            else -> false
        }
    }

    fun tryInjectKey(context: Context, data: ByteArray): Boolean {
        if (!hasInjectPermission(context)) {
            return false
        }
        val keyEvent = KeyEvent.parseFrom(data)
        val events = when {
            keyEvent.hasSeq() -> keyEventsFromText(keyEvent.seq)
            keyEvent.hasUnicode() -> keyEventsFromText(String(Character.toChars(keyEvent.unicode)))
            else -> keyEventsFromProto(keyEvent)
        }
        if (events.isEmpty()) {
            return false
        }
        for (event in events) {
            setInputSource(event, InputDevice.SOURCE_KEYBOARD)
            if (!injectInputEvent(context, event)) {
                return false
            }
        }
        return true
    }

    private fun keyEventsFromText(text: String): List<KeyEventAndroid> {
        if (text.isEmpty()) {
            return emptyList()
        }
        val events = KeyCharacterMap.load(KeyCharacterMap.VIRTUAL_KEYBOARD).getEvents(text.toCharArray())
            ?: return emptyList()
        return events.toList()
    }

    private fun keyEventsFromProto(keyEvent: KeyEvent): List<KeyEventAndroid> {
        val event = KeyEventConverter.toAndroidKeyEvent(keyEvent)
        if (event.keyCode == KeyEventAndroid.KEYCODE_UNKNOWN || event.keyCode == 0) {
            return emptyList()
        }
        if (!keyEvent.press) {
            return listOf(event)
        }
        val upEvent = KeyEventAndroid(
            event.downTime,
            SystemClock.uptimeMillis(),
            KeyEventAndroid.ACTION_UP,
            event.keyCode,
            0,
            event.metaState,
            event.deviceId,
            event.scanCode,
            event.flags,
            InputDevice.SOURCE_KEYBOARD
        )
        return listOf(event, upEvent)
    }

    private fun injectMouse(context: Context, mask: Int, x: Int, y: Int): Boolean {
        if (mask == 0 || mask == LEFT_MOVE) {
            mouseX = scaleAbs(x)
            mouseY = scaleAbs(y)
            if (mouseDown) {
                return injectMotion(context, MotionEvent.ACTION_MOVE, mouseX, mouseY, mouseDownTime)
            }
            return true
        }

        when (mask) {
            LEFT_DOWN -> {
                mouseX = scaleAbs(x)
                mouseY = scaleAbs(y)
                val now = SystemClock.uptimeMillis()
                val ok = injectMotion(context, MotionEvent.ACTION_DOWN, mouseX, mouseY, now)
                mouseDown = ok
                mouseDownTime = if (ok) now else 0L
                return ok
            }
            LEFT_UP -> {
                mouseX = scaleAbs(x)
                mouseY = scaleAbs(y)
                val ok = if (mouseDown) {
                    injectMotion(context, MotionEvent.ACTION_UP, mouseX, mouseY, mouseDownTime)
                } else {
                    true
                }
                mouseDown = false
                mouseDownTime = 0L
                return ok
            }
            RIGHT_UP -> {
                mouseX = scaleAbs(x)
                mouseY = scaleAbs(y)
                return injectLongPress(context, mouseX, mouseY)
            }
            BACK_UP -> {
                return injectKeyCode(context, KeyEventAndroid.KEYCODE_BACK)
            }
            WHEEL_BUTTON_DOWN -> {
                scheduleRecents(context)
                return true
            }
            WHEEL_BUTTON_UP -> {
                return handleWheelButtonUp(context)
            }
            WHEEL_DOWN -> {
                return injectWheelSwipe(context, -WHEEL_STEP)
            }
            WHEEL_UP -> {
                return injectWheelSwipe(context, WHEEL_STEP)
            }
            else -> return false
        }
    }

    private fun injectTouch(context: Context, mask: Int, x: Int, y: Int): Boolean {
        when (mask) {
            TOUCH_PAN_START -> {
                touchX = scaleAbs(x)
                touchY = scaleAbs(y)
                val now = SystemClock.uptimeMillis()
                val ok = injectMotion(context, MotionEvent.ACTION_DOWN, touchX, touchY, now)
                touchDown = ok
                touchDownTime = if (ok) now else 0L
                return ok
            }
            TOUCH_PAN_UPDATE -> {
                touchX -= scaleDelta(x)
                touchY -= scaleDelta(y)
                if (touchX < 0f) {
                    touchX = 0f
                }
                if (touchY < 0f) {
                    touchY = 0f
                }
                if (touchDown) {
                    return injectMotion(context, MotionEvent.ACTION_MOVE, touchX, touchY, touchDownTime)
                }
                return true
            }
            TOUCH_PAN_END -> {
                val ok = if (touchDown) {
                    injectMotion(context, MotionEvent.ACTION_UP, touchX, touchY, touchDownTime)
                } else {
                    true
                }
                touchDown = false
                touchDownTime = 0L
                touchX = scaleAbs(x)
                touchY = scaleAbs(y)
                return ok
            }
            else -> return false
        }
    }

    private fun injectWheelSwipe(context: Context, deltaY: Int): Boolean {
        if (mouseY < WHEEL_STEP.toFloat()) {
            return true
        }
        val startX = mouseX
        val startY = mouseY
        val endY = max(0f, startY + deltaY.toFloat())
        val downTime = SystemClock.uptimeMillis()
        val moveTime = downTime + WHEEL_DURATION
        val upTime = moveTime + 1
        val okDown = injectMotion(context, MotionEvent.ACTION_DOWN, startX, startY, downTime, downTime)
        val okMove = injectMotion(context, MotionEvent.ACTION_MOVE, startX, endY, downTime, moveTime)
        val okUp = injectMotion(context, MotionEvent.ACTION_UP, startX, endY, downTime, upTime)
        return okDown && okMove && okUp
    }

    private fun scheduleRecents(context: Context) {
        recentActionRunnable?.let { handler.removeCallbacks(it) }
        val runnable = Runnable {
            injectKeyCode(context, KeyEventAndroid.KEYCODE_APP_SWITCH)
            recentActionRunnable = null
        }
        recentActionRunnable = runnable
        handler.postDelayed(runnable, LONG_TAP_DELAY)
    }

    private fun handleWheelButtonUp(context: Context): Boolean {
        val runnable = recentActionRunnable
        return if (runnable != null) {
            handler.removeCallbacks(runnable)
            recentActionRunnable = null
            injectKeyCode(context, KeyEventAndroid.KEYCODE_HOME)
        } else {
            true
        }
    }

    private fun injectLongPress(context: Context, x: Float, y: Float): Boolean {
        val downTime = SystemClock.uptimeMillis()
        val okDown = injectMotion(context, MotionEvent.ACTION_DOWN, x, y, downTime)
        if (!okDown) {
            return false
        }
        handler.postDelayed({
            injectMotion(context, MotionEvent.ACTION_UP, x, y, downTime)
        }, longPressDuration)
        return true
    }

    private fun injectKeyCode(context: Context, keyCode: Int): Boolean {
        val downTime = SystemClock.uptimeMillis()
        val down = KeyEventAndroid(downTime, downTime, KeyEventAndroid.ACTION_DOWN, keyCode, 0)
        val up = KeyEventAndroid(downTime, downTime + 10, KeyEventAndroid.ACTION_UP, keyCode, 0)
        setInputSource(down, InputDevice.SOURCE_KEYBOARD)
        setInputSource(up, InputDevice.SOURCE_KEYBOARD)
        val okDown = injectInputEvent(context, down)
        val okUp = injectInputEvent(context, up)
        return okDown && okUp
    }

    private fun injectMotion(
        context: Context,
        action: Int,
        x: Float,
        y: Float,
        downTime: Long,
        eventTime: Long = SystemClock.uptimeMillis()
    ): Boolean {
        val event = MotionEvent.obtain(downTime, eventTime, action, x, y, 0)
        setInputSource(event, InputDevice.SOURCE_TOUCHSCREEN)
        val ok = injectInputEvent(context, event)
        event.recycle()
        return ok
    }

    private fun hasInjectPermission(context: Context): Boolean {
        return ContextCompat.checkSelfPermission(context, injectPermission) ==
            PackageManager.PERMISSION_GRANTED
    }

    private fun injectInputEvent(context: Context, event: InputEvent): Boolean {
        val inputManager = context.getSystemService(Context.INPUT_SERVICE) as? InputManager
            ?: return false
        return try {
            val method = inputManager.javaClass.getDeclaredMethod(
                "injectInputEvent",
                InputEvent::class.java,
                Int::class.javaPrimitiveType
            )
            method.isAccessible = true
            val mode = resolveInjectMode(inputManager)
            (method.invoke(inputManager, event, mode) as? Boolean) == true
        } catch (e: Exception) {
            Log.d(logTag, "injectInputEvent failed: ${e.javaClass.simpleName}: ${e.message}")
            false
        }
    }

    private fun resolveInjectMode(inputManager: InputManager): Int {
        val names = listOf(
            "INJECT_INPUT_EVENT_MODE_ASYNC",
            "INJECT_INPUT_EVENT_MODE_WAIT_FOR_RESULT",
            "INJECT_INPUT_EVENT_MODE_WAIT_FOR_FINISH",
        )
        for (name in names) {
            try {
                val field = inputManager.javaClass.getDeclaredField(name)
                field.isAccessible = true
                return field.getInt(null)
            } catch (_: Exception) {
                // try next
            }
        }
        return 0
    }

    private fun setInputSource(event: InputEvent, source: Int) {
        try {
            val method = event.javaClass.getMethod("setSource", Int::class.javaPrimitiveType)
            method.invoke(event, source)
        } catch (e: Exception) {
            Log.d(logTag, "setSource failed: ${e.javaClass.simpleName}: ${e.message}")
        }
    }

    private fun scaleAbs(value: Int): Float {
        val scaled = max(0, value) * SCREEN_INFO.scale
        return scaled.toFloat()
    }

    private fun scaleDelta(value: Int): Float {
        return value.toFloat() * SCREEN_INFO.scale.toFloat()
    }
}
