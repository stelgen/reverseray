package dev.stelgen.reverseray

import android.view.View
import android.view.ViewGroup
import android.widget.Button

/** Рекурсивный обход дерева UI для тестов (M3: элементы во вложенных контейнерах). */
object UiFind {
    fun buttons(root: View): List<Button> {
        val out = mutableListOf<Button>()
        walk(root) { v -> if (v is Button) out.add(v) }
        return out
    }

    fun editTexts(root: View): List<android.widget.EditText> {
        val out = mutableListOf<android.widget.EditText>()
        walk(root) { v -> if (v is android.widget.EditText) out.add(v) }
        return out
    }

    fun texts(root: View): List<android.widget.TextView> {
        val out = mutableListOf<android.widget.TextView>()
        walk(root) { v -> if (v is android.widget.TextView) out.add(v) }
        return out
    }

    fun allViews(root: View): List<View> {
        val out = mutableListOf<View>()
        walk(root) { out.add(it) }
        return out
    }

    private fun walk(v: View, visit: (View) -> Unit) {
        visit(v)
        if (v is ViewGroup) {
            for (i in 0 until v.childCount) walk(v.getChildAt(i), visit)
        }
    }

    fun contentView(activity: android.app.Activity): ViewGroup =
        activity.findViewById<ViewGroup>(android.R.id.content).getChildAt(0) as ViewGroup
}
