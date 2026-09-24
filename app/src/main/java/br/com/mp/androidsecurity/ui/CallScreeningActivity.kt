package br.com.mp.androidsecurity.ui

import android.app.Activity
import android.app.AlertDialog
import android.app.role.RoleManager
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.graphics.Typeface
import android.view.Gravity
import android.widget.*
import br.com.mp.androidsecurity.call.CallRules

class CallScreeningActivity : Activity() {
    private lateinit var status: TextView
    private lateinit var logsText: TextView

    override fun onCreate(state: Bundle?) { super.onCreate(state); buildUi() }
    override fun onResume() { super.onResume(); if (::status.isInitialized) refresh() }

    private fun buildUi() {
        val scroll = ScrollView(this)
        val root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(28, 28, 28, 40) }
        scroll.addView(root)
        root.addView(TextView(this).apply { text = "Filtragem de chamadas"; textSize = 27f; setTypeface(null, Typeface.BOLD) })
        status = TextView(this).apply { textSize = 17f; setPadding(0, 12, 0, 12) }; root.addView(status)
        root.addView(Button(this).apply { text = "ATIVAR FILTRAGEM DE CHAMADAS"; setOnClickListener { requestRole() } })
        addCheck(root, "Bloquear números desconhecidos", "block_unknown")
        addCheck(root, "Bloquear chamadas privadas/sem número", "block_private")
        addList(root, "Número bloqueado", "blocked_numbers")
        addList(root, "Número permitido", "allowed_numbers")
        addList(root, "Prefixo bloqueado", "blocked_prefixes")
        root.addView(TextView(this).apply { text = "PIN de proteção"; textSize = 19f; setTypeface(null, Typeface.BOLD); setPadding(0, 20, 0, 6) })
        root.addView(Button(this).apply { text = if (CallRules.hasPin(this@CallScreeningActivity)) "ALTERAR/REMOVER PIN" else "CRIAR PIN"; setOnClickListener { pinDialog() } })
        root.addView(TextView(this).apply { text = "Histórico de chamadas bloqueadas"; textSize = 19f; setTypeface(null, Typeface.BOLD); setPadding(0, 20, 0, 6) })
        logsText = TextView(this); root.addView(logsText)
        root.addView(Button(this).apply { text = "LIMPAR HISTÓRICO"; setOnClickListener { CallRules.clearLogs(this@CallScreeningActivity); refresh() } })
        setContentView(scroll); refresh()
    }

    private fun addCheck(root: LinearLayout, label: String, key: String) {
        val check = CheckBox(this).apply { text = label; isChecked = CallRules.get(this@CallScreeningActivity, key, false) }
        check.setOnCheckedChangeListener { _, value -> CallRules.set(this, key, value) }
        root.addView(check)
    }

    private fun addList(root: LinearLayout, hint: String, key: String) {
        val row = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL }
        val input = EditText(this).apply { this.hint = hint; inputType = 2; layoutParams = LinearLayout.LayoutParams(0, -2, 1f) }
        val add = Button(this).apply { text = "+" }
        row.addView(input); row.addView(add); root.addView(row)
        val listView = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }; root.addView(listView)
        fun render() {
            listView.removeAllViews()
            CallRules.list(this, key).sorted().forEach { value ->
                val rowItem = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
                rowItem.addView(TextView(this).apply { text = value; layoutParams = LinearLayout.LayoutParams(0, -2, 1f); setPadding(8, 8, 8, 8) })
                rowItem.addView(Button(this).apply { text = "Remover"; setOnClickListener { CallRules.remove(this@CallScreeningActivity, key, value); render() } })
                listView.addView(rowItem)
            }
        }
        add.setOnClickListener { val value = CallRules.normalize(input.text.toString()); if (value.isNotBlank()) { CallRules.add(this, key, value); input.text.clear(); render() } }
        render()
    }

    private fun requestRole() {
        if (Build.VERSION.SDK_INT >= 29) {
            val role = getSystemService(RoleManager::class.java)
            if (role.isRoleAvailable(RoleManager.ROLE_CALL_SCREENING) && !role.isRoleHeld(RoleManager.ROLE_CALL_SCREENING)) {
                startActivityForResult(role.createRequestRoleIntent(RoleManager.ROLE_CALL_SCREENING), 2001); return
            }
        }
        startActivity(Intent(Settings.ACTION_MANAGE_DEFAULT_APPS_SETTINGS))
    }

    private fun pinDialog() {
        val input = EditText(this).apply { hint = "PIN 4-8 dígitos"; inputType = 2 }
        AlertDialog.Builder(this).setTitle("PIN de proteção").setView(input)
            .setPositiveButton("Salvar") { _, _ -> if (input.text.length in 4..8) CallRules.setPin(this, input.text.toString()) }
            .setNeutralButton(if (CallRules.hasPin(this)) "Remover PIN" else "Cancelar") { _, _ -> if (CallRules.hasPin(this)) CallRules.removePin(this) }
            .setNegativeButton("Fechar", null).show()
    }

    private fun refresh() {
        val active = Build.VERSION.SDK_INT >= 29 && getSystemService(RoleManager::class.java).isRoleHeld(RoleManager.ROLE_CALL_SCREENING)
        status.text = if (active) "● Filtragem ativa" else "○ Filtragem inativa"
        val logs = CallRules.logs(this).toList().sortedDescending()
        logsText.text = if (logs.isEmpty()) "Nenhuma chamada bloqueada ainda." else logs.joinToString("\n")
    }
}
