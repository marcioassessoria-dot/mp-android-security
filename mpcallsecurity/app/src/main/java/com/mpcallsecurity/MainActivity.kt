package com.mpcallsecurity

import android.app.Activity
import android.app.AlertDialog
import android.app.role.RoleManager
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.view.Gravity
import android.graphics.Typeface
import android.widget.*

class MainActivity : Activity() {
    private lateinit var status: TextView
    private lateinit var diagnostic: TextView
    private lateinit var stats: TextView
    private lateinit var logsText: TextView
    override fun onCreate(savedInstanceState: Bundle?) { super.onCreate(savedInstanceState); buildUi() }
    override fun onResume() { super.onResume(); if (::status.isInitialized) refresh() }
    private fun buildUi() {
        val scroll=ScrollView(this); val root=LinearLayout(this).apply{orientation=LinearLayout.VERTICAL;setPadding(28,28,28,40)};scroll.addView(root)
        root.addView(TextView(this).apply{text="MP Call Security";textSize=29f;setTypeface(null,Typeface.BOLD)})
        root.addView(TextView(this).apply{text="Proteção contra chamadas indesejadas";textSize=15f;setPadding(0,4,0,16)})
        status=TextView(this).apply{textSize=17f;setTypeface(null,Typeface.BOLD);setPadding(16,16,16,16)};root.addView(status)
        diagnostic=TextView(this).apply{textSize=13f;setPadding(16,4,16,12)};root.addView(diagnostic)
        root.addView(Button(this).apply{text="ATIVAR FILTRAGEM DE CHAMADAS";setOnClickListener{requestCallScreeningRole()}})
        root.addView(Button(this).apply{text="ABRIR CONFIGURAÇÃO DO TELEFONE";setOnClickListener{startActivity(Intent(Settings.ACTION_MANAGE_DEFAULT_APPS_SETTINGS))}})
        stats=TextView(this).apply{textSize=15f;setPadding(0,10,0,18)};root.addView(stats)
        root.addView(section("Regras de proteção"));addCheck(root,"Bloquear números desconhecidos","block_unknown");addCheck(root,"Bloquear chamadas privadas/sem número","block_private")
        root.addView(section("Lista negra"));addListEditor(root,"Número completo","blocked_numbers")
        root.addView(section("Lista permitida (prioridade máxima)"));addListEditor(root,"Número que nunca será bloqueado","allowed_numbers")
        root.addView(section("Prefixos bloqueados"));addListEditor(root,"Ex.: 4499","blocked_prefixes")
        root.addView(section("Proteção das configurações"));root.addView(Button(this).apply{text=if(CallRules.hasPin(this@MainActivity))"ALTERAR/REMOVER PIN" else "CRIAR PIN";setOnClickListener{pinDialog()}})
        root.addView(section("Histórico"));logsText=TextView(this).apply{textSize=14f};root.addView(logsText);root.addView(Button(this).apply{text="Limpar histórico";setOnClickListener{CallRules.clearLogs(this@MainActivity);refresh()}})
        root.addView(TextView(this).apply{text="O bloqueio é feito pelo CallScreeningService do Android. O sistema precisa reconhecer este app como o app de filtragem de chamadas.";textSize=13f;setPadding(0,18,0,0)})
        setContentView(scroll);refresh()
    }
    private fun section(t:String)=TextView(this).apply{text=t;textSize=19f;setTypeface(null,Typeface.BOLD);setPadding(0,20,0,6)}
    private fun addCheck(root:LinearLayout,label:String,key:String){val c=CheckBox(this).apply{text=label;isChecked=CallRules.get(this@MainActivity,key,false)};c.setOnCheckedChangeListener{_,v->CallRules.set(this,key,v)};root.addView(c)}
    private fun addListEditor(parent:LinearLayout,hint:String,key:String){val row=LinearLayout(this).apply{orientation=LinearLayout.HORIZONTAL;gravity=Gravity.CENTER_VERTICAL};val input=EditText(this).apply{this.hint=hint;inputType=2;layoutParams=LinearLayout.LayoutParams(0,-2,1f)};val add=Button(this).apply{text="+"};row.addView(input);row.addView(add);parent.addView(row);val listView=LinearLayout(this).apply{orientation=LinearLayout.VERTICAL};parent.addView(listView);fun render(){listView.removeAllViews();val items=CallRules.list(this,key).toList().sorted();if(items.isEmpty())listView.addView(TextView(this).apply{text="Nenhum item cadastrado";setPadding(8,8,8,8)});items.forEach{v->val r=LinearLayout(this).apply{orientation=LinearLayout.HORIZONTAL;gravity=Gravity.CENTER_VERTICAL};r.addView(TextView(this).apply{text=v;textSize=15f;layoutParams=LinearLayout.LayoutParams(0,-2,1f);setPadding(8,8,8,8)});r.addView(Button(this).apply{text="Remover";setOnClickListener{CallRules.remove(this@MainActivity,key,v);render();refresh()}});listView.addView(r)}};add.setOnClickListener{val v=CallRules.normalize(input.text.toString());if(v.isBlank())input.error="Informe um valor"else{CallRules.add(this,key,v);input.text.clear();render();refresh()}};render()}
    private fun requestCallScreeningRole(){
        if(Build.VERSION.SDK_INT>=29){val rm=getSystemService(RoleManager::class.java);if(rm.isRoleAvailable(RoleManager.ROLE_CALL_SCREENING)){if(!rm.isRoleHeld(RoleManager.ROLE_CALL_SCREENING)){startActivityForResult(rm.createRequestRoleIntent(RoleManager.ROLE_CALL_SCREENING),2001)}else Toast.makeText(this,"MP Call Security já está ativo",Toast.LENGTH_SHORT).show();return}}
        Toast.makeText(this,"Seu Android não disponibilizou a função de filtragem de chamadas para este dispositivo.",Toast.LENGTH_LONG).show();startActivity(Intent(Settings.ACTION_MANAGE_DEFAULT_APPS_SETTINGS))
    }
    private fun isActive()=Build.VERSION.SDK_INT>=29&&getSystemService(RoleManager::class.java).isRoleHeld(RoleManager.ROLE_CALL_SCREENING)
    private fun pinDialog(){val input=EditText(this).apply{hint="PIN com 4 a 8 dígitos";inputType=2};AlertDialog.Builder(this).setTitle(if(CallRules.hasPin(this))"Proteção por PIN" else "Criar PIN").setView(input).setPositiveButton("Salvar"){_,_->val p=input.text.toString();if(p.length in 4..8)CallRules.setPin(this,p)else Toast.makeText(this,"Use de 4 a 8 dígitos",Toast.LENGTH_SHORT).show();refresh()}.setNeutralButton(if(CallRules.hasPin(this))"ALTERAR/REMOVER PIN" else "Cancelar"){_,_->if(CallRules.hasPin(this))CallRules.removePin(this);refresh()}.setNegativeButton("Cancelar",null).show()}
    private fun refresh(){val active=isActive();status.text=if(active)"● FILTRAGEM ATIVA" else "○ FILTRAGEM INATIVA";val available=Build.VERSION.SDK_INT>=29&&getSystemService(RoleManager::class.java).isRoleAvailable(RoleManager.ROLE_CALL_SCREENING);diagnostic.text="Status do Android: função disponível=$available • função atribuída=$active";val logItems: List<String> = CallRules.logs(this).toList();stats.text="Bloqueios: ${logItems.size} • Lista negra: ${CallRules.list(this,"blocked_numbers").size} • Prefixos: ${CallRules.list(this,"blocked_prefixes").size}";logsText.text=if(logItems.isEmpty())"Nenhuma chamada bloqueada ainda." else logItems.joinToString(separator="\n")}
}
