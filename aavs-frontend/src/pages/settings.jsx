import React, { useState } from 'react'

export default function SettingsPage() {
  const [settings, setSettings] = useState({
    baseUrl:'', authType:'Bearer Token', token:'', timeout:30, retries:2,
    rateLimit:10, concurrency:5, passive:true, aggressive:false,
    reports:['PDF','JSON'], darkMode:true, email:''
  })

  const update=(k,v)=>setSettings(s=>({...s,[k]:v}))
  const toggleReport=(type)=>{
    const has=settings.reports.includes(type)
    update('reports', has ? settings.reports.filter(x=>x!==type) : [...settings.reports,type])
  }

  const save = () => alert('Settings saved. Civilization limps onward.')

  const Section=({title,children})=>(
    <div className='bg-slate-900/80 backdrop-blur border border-purple-800/40 rounded-2xl shadow-xl p-6 space-y-4'>
      <h2 className='text-xl font-semibold text-purple-300'>{title}</h2>
      {children}
    </div>
  )

  const Input=(props)=><input {...props} className='w-full border border-purple-800/40 bg-slate-950/70 text-gray-200 rounded-xl px-3 py-2 focus:outline-none focus:ring-2 focus:ring-indigo-500' />

  return (
    <div className='min-h-screen bg-gradient-to-br from-slate-950 via-indigo-950 to-purple-950 p-6'>
      <div className='max-w-6xl mx-auto space-y-6'>
        <div className='flex items-center justify-between'>
          <div>
            <h1 className='text-3xl font-bold text-indigo-300'>Scanner Settings</h1>
            <p className='text-gray-400'>Configure your automated API scanner. Try not to attack production by accident.</p>
          </div>
          <button onClick={save} className='bg-gradient-to-r from-indigo-600 to-purple-600 text-white px-5 py-2 rounded-2xl'>Save</button>
        </div>

        <div className='grid md:grid-cols-2 gap-6'>
          <Section title='Target & Network'>
            <div>
              <label className='text-sm font-medium text-gray-300'>Base URL</label>
              <Input value={settings.baseUrl} onChange={e=>update('baseUrl',e.target.value)} placeholder='https://api.example.com' />
            </div>
            <div>
              <label className='text-sm font-medium text-gray-300'>Timeout (sec)</label>
              <Input type='number' value={settings.timeout} onChange={e=>update('timeout',+e.target.value)} />
            </div>
            <div>
              <label className='text-sm font-medium text-gray-300'>Retries</label>
              <Input type='number' value={settings.retries} onChange={e=>update('retries',+e.target.value)} />
            </div>
            <div>
              <label className='text-sm font-medium text-gray-300'>Requests / sec</label>
              <Input type='number' value={settings.rateLimit} onChange={e=>update('rateLimit',+e.target.value)} />
            </div>
          </Section>

          <Section title='Authentication'>
            <select value={settings.authType} onChange={e=>update('authType',e.target.value)} className='w-full border border-purple-800/40 bg-slate-950/70 text-gray-200 rounded-xl px-3 py-2 focus:outline-none focus:ring-2 focus:ring-indigo-500'>
              <option>None</option>
              <option>API Key</option>
              <option>Bearer Token</option>
              <option>Basic Auth</option>
              <option>OAuth2</option>
            </select>
            <div>
              <label className='text-sm font-medium text-gray-300'>Secret / Token</label>
              <Input type='password' value={settings.token} onChange={e=>update('token',e.target.value)} placeholder='••••••••' />
            </div>
          </Section>

          <Section title='Scan Modes'>
            <label className='flex items-center gap-3'><input type='checkbox' checked={settings.passive} onChange={e=>update('passive',e.target.checked)} /> Passive Scan</label>
            <label className='flex items-center gap-3'><input type='checkbox' checked={settings.aggressive} onChange={e=>update('aggressive',e.target.checked)} /> Aggressive Tests</label>
            <div>
              <label className='text-sm font-medium text-gray-300'>Concurrency</label>
              <Input type='number' value={settings.concurrency} onChange={e=>update('concurrency',+e.target.value)} />
            </div>
          </Section>

          <Section title='Reports & Alerts'>
            <div className='space-y-2'>
              {['PDF','JSON','CSV','HTML'].map(type => (
                <label key={type} className='flex items-center gap-3'>
                  <input type='checkbox' checked={settings.reports.includes(type)} onChange={()=>toggleReport(type)} /> {type}
                </label>
              ))}
            </div>
            <div>
              <label className='text-sm font-medium text-gray-300'>Alert Email</label>
              <Input type='email' value={settings.email} onChange={e=>update('email',e.target.value)} placeholder='security@company.com' />
            </div>
          </Section>
        </div>

        <Section title='Appearance'>
          <label className='flex items-center gap-3'><input type='checkbox' checked={settings.darkMode} onChange={e=>update('darkMode',e.target.checked)} /> Dark Mode</label>
        </Section>
      </div>
    </div>
  )
}
