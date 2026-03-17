
import requireLogin from "../middlewares/auth.middlewares.ts"
import { firewallService } from "../../index.ts"
import { Router } from "express"
import { targetsList, Protocols } from "../services/iptables.ts"

const router = Router()

// <allow / deny> * traffic from an IP
router.post('/ip', requireLogin, async (req, res) => {
    const { ip, target } = req.body

    console.debug(target, ip)

    if (!target || targetsList.includes(target.toLowerCase())) return res.status(400).json({ type: "bad" })
    if (!ip) return res.status(400).json({ type: "bad" })

    try {
        const data = await firewallService.ip(ip, target)
        if (!data) throw new Error(`Failed to ${targetsList[target]} traffic from IP`)

        return res.json({ type: "ok" })
    } catch (err) {
        console.error(`Failed to ${targetsList[target]} traffic from an IP: ${err}`)
        return res.status(500).json({ type: "failed" })
    }
})

// <allow / deny> port traffic from an IP
router.post('/ip-port', requireLogin, async (req, res) => {
    const { ip, port, target } = req.body

    if (!target || !targetsList.includes(target)) return res.status(400).json({ type: "bad" })
    if (!ip || !port) return res.status(400).json({ type: "bad" })

    try {
        const data = await firewallService.portForIp(port, ip, Protocols.tcp, target)
        if (!data) throw new Error("Failed to deny port traffic from IP")

        return res.json({ type: "ok" })
    } catch (err) {
        console.error(`Failed to ${targetsList[target]} port traffic from IP: ${err}`)
        return res.status(500).json({ type: "failed" })
    }
})

// <open / close> port
router.post(`/port`, requireLogin, async (req, res) => {
    const { port, target, protocol } = req.body

    if (!target || !targetsList.includes(target)) return res.status(400).json({ type: "bad" })
    if (!port) return res.status(400).json({ type: "bad" })

    try {
        const data = await firewallService.port(port, protocol, target)
        if (!data) throw new Error(`Failed to ${targetsList[target]} port`)

        return res.json({ type: "ok" })
    } catch (err) {
        console.error(`Failed to ${targetsList[target]} port: ${err}`)
        return res.status(500).json({ type: "failed" })
    }
})

export default router