import { createRouter, createWebHistory } from 'vue-router'
import Home from '@/views/Home.vue'
import ProbeTest from '@/views/ProbeTest.vue'
import PricePage from '@/views/PricePage.vue'
import Dashboard from '@/views/Dashboard.vue'
import BotDetection from '@/views/BotDetection.vue'
import IpGeoLab from '@/views/IpGeoLab.vue'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', name: 'home', component: Home },
    { path: '/probes', name: 'probes', component: ProbeTest },
    { path: '/bot-check', name: 'bot-check', component: BotDetection },
    { path: '/ip-intel', name: 'ip-intel', component: IpGeoLab },
    { path: '/price', name: 'price', component: PricePage },
    { path: '/dashboard', name: 'dashboard', component: Dashboard },
  ],
})

export default router
