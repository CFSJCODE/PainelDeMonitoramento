import "dotenv/config";
import express from "express";
import cors from "cors";
import fetch from "node-fetch";
import https from "https";
import getSslCertificate from "get-ssl-certificate";
import dns from "dns/promises";
import pino from "pino";

// ===================================================================================
// 1. CONFIGURAÇÃO CENTRAL
// ===================================================================================
const Config = {
  CHECK_INTERVAL: 60 * 1000, // 60 segundos
  LATENCY_DEGRADED_THRESHOLD: 1500, // 1.5 segundos
  BROWSER_USER_AGENT:
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
  services: {
    modem_claro: {
      url: "http://192.168.0.1/",
      name: "Modem Claro (Gateway)",
      checkType: "http",
      requiredContent: ["claro", "status", "conectado", "connected"],
    },
    chat_gpt: {
      url: "https://status.openai.com/",
      name: "ChatGPT",
      checkType: "http",
    },
    google_gemini: {
      url: "https://aistudio.google.com/status",
      name: "Google Gemini",
      checkType: "http",
    },
    microsoft_copilot: {
      url: "https://status.cloud.microsoft/",
      name: "Microsoft Copilot",
      checkType: "http",
    },
    perplexity_ai: {
      url: "https://www.perplexity.ai/",
      name: "Perplexity AI",
      checkType: "http",
    },
    spotify: {
      url: "https://status.spotify.com/api/v2/summary.json",
      name: "Spotify",
      checkType: "statuspage",
    },
    globoplay: {
      url: "https://globoplay.globo.com/",
      name: "Globoplay",
      checkType: "http",
      forbiddenContent: ["indisponível", "manutenção"],
    },
    puc_minas: {
      url: "https://www.pucminas.br/",
      name: "PUC Minas",
      checkType: "http",
      ignoreSsl: true,
    },
    tjmg: { url: "https://www.tjmg.jus.br/", name: "TJMG", checkType: "http" },
    pje: { url: "https://pje.tjmg.jus.br/", name: "PJe", checkType: "http" },
    meu_inss: {
      url: "https://meu.inss.gov.br/",
      name: "Meu INSS",
      checkType: "http",
      forbiddenContent: ["serviço temporariamente indisponível"],
    },
    google_cloud: {
      url: "https://status.cloud.google.com/",
      name: "Google Cloud",
      checkType: "http",
    },
    microsoft_365: {
      url: "https://status.cloud.microsoft/m365/",
      name: "Microsoft 365",
      checkType: "http",
    },
    printer_clx3300: {
      url: "http://192.168.0.11/sws/index.html",
      name: "Impressora CLX-3300",
      checkType: "http",
      requiredContent: ["pronta", "ready"],
    },
    printer_m4070fr: {
      url: "http://192.168.0.20/sws/index.html",
      name: "Impressora M4070FR",
      checkType: "http",
      requiredContent: ["pronta", "ready"],
    },
  },
};

// ===================================================================================
// 2. CLASSES DE VERIFICAÇÃO (CHECKERS)
// ===================================================================================
class BaseChecker {
  constructor(id, config) {
    if (this.constructor === BaseChecker) {
      throw new Error(
        "A classe base 'BaseChecker' não pode ser instanciada diretamente."
      );
    }
    this.id = id;
    this.config = config;
  }
  async check() {
    throw new Error("O método 'check' deve ser implementado pela subclasse.");
  }
}

class HttpChecker extends BaseChecker {
  async check() {
    const result = {
      id: this.id,
      name: this.config.name,
      url: this.config.url,
      status: "UNKNOWN",
      ip: null,
      latency: null,
      statusCode: null,
      ssl: { valid: null, expires_in_days: null },
      error: null,
      lastChecked: new Date().toISOString(),
    };

    try {
      const url = new URL(this.config.url);

      await this.checkDns(url.hostname, result);
      if (url.protocol === "https:") {
        await this.checkSsl(url.hostname, result);
      }

      const agent = this.config.ignoreSsl
        ? new https.Agent({ rejectUnauthorized: false })
        : undefined;

      const startTime = Date.now();
      const response = await fetch(this.config.url, {
        agent,
        timeout: 15000,
        headers: { "User-Agent": Config.BROWSER_USER_AGENT },
      });
      result.latency = Date.now() - startTime;
      result.statusCode = response.status;

      await this.evaluateResponse(response, result);
    } catch (err) {
      result.status = "MAJOR_OUTAGE";
      result.error = err.code || err.message;
    }
    return result;
  }

  async checkDns(hostname, result) {
    if (!hostname.match(/^[0-9.]+$/)) {
      const { address } = await dns.lookup(hostname);
      result.ip = address;
    } else {
      result.ip = hostname;
    }
  }

  async checkSsl(hostname, result) {
    try {
      const certificate = await getSslCertificate.get(hostname, {
        timeout: 5000,
      });
      result.ssl.valid = true;
      const expiryDate = new Date(certificate.valid_to);
      result.ssl.expires_in_days = Math.floor(
        (expiryDate - Date.now()) / (1000 * 60 * 60 * 24)
      );
    } catch (sslError) {
      result.ssl.valid = false;
    }
  }

  async evaluateResponse(response, result) {
    if (response.ok || response.status === 403) {
      const textContent = await response.text();
      if (
        this.config.forbiddenContent?.some((word) =>
          textContent.toLowerCase().includes(word)
        )
      ) {
        result.status = "MAJOR_OUTAGE";
        result.error = "Conteúdo de erro encontrado na página.";
      } else if (
        this.config.requiredContent &&
        !this.config.requiredContent.some((word) =>
          textContent.toLowerCase().includes(word)
        )
      ) {
        result.status = "MAJOR_OUTAGE";
        result.error = "Palavra-chave de status não encontrada.";
      } else {
        result.status = "OPERATIONAL";
      }
      if (
        result.status === "OPERATIONAL" &&
        result.latency > Config.LATENCY_DEGRADED_THRESHOLD
      ) {
        result.status = "DEGRADED";
      }
    } else {
      result.status = "MAJOR_OUTAGE";
      result.error = `Status Code: ${response.status}`;
    }
  }
}

class StatusPageChecker extends BaseChecker {
  async check() {
    const result = {
      id: this.id,
      name: this.config.name,
      url: this.config.url,
      status: "UNKNOWN",
      error: null,
      lastChecked: new Date().toISOString(),
    };
    try {
      const startTime = Date.now();
      const response = await fetch(this.config.url, { timeout: 10000 });
      result.latency = Date.now() - startTime;
      result.statusCode = response.status;
      if (!response.ok) throw new Error(`Status Code: ${response.status}`);

      const data = await response.json();
      const indicator = data.status?.indicator;

      switch (indicator) {
        case "none":
          result.status = "OPERATIONAL";
          break;
        case "minor":
          result.status = "DEGRADED";
          result.error = data.status.description;
          break;
        default:
          result.status = "MAJOR_OUTAGE";
          result.error = data.status.description;
          break;
      }
    } catch (err) {
      result.status = "MAJOR_OUTAGE";
      result.error = err.message;
    }
    return result;
  }
}

// ===================================================================================
// 3. SERVIÇOS DE NEGÓCIO
// ===================================================================================
class SseService {
  constructor(logger) {
    this.clients = new Map();
    this.logger = logger.child({ service: "SseService" });
  }

  addClient(res) {
    const clientId = Date.now();
    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Connection", "keep-alive");
    res.setHeader("Cache-Control", "no-cache");
    res.flushHeaders();

    this.clients.set(clientId, res);
    this.logger.info(
      `Cliente SSE [${clientId}] conectado. Total: ${this.clients.size}`
    );

    res.on("close", () => {
      this.clients.delete(clientId);
      this.logger.info(
        `Cliente SSE [${clientId}] desconectado. Total: ${this.clients.size}`
      );
    });

    return clientId;
  }

  sendToAll(data) {
    if (this.clients.size === 0) return;
    const sseFormattedData = `data: ${JSON.stringify(data)}\n\n`;
    for (const res of this.clients.values()) {
      res.write(sseFormattedData);
    }
  }

  sendToOne(clientId, data) {
    const clientRes = this.clients.get(clientId);
    if (clientRes) {
      clientRes.write(`data: ${JSON.stringify(data)}\n\n`);
    }
  }
}

class StatusService {
  constructor(servicesConfig, sseService, logger) {
    this.servicesConfig = servicesConfig;
    this.sseService = sseService;
    this.logger = logger.child({ service: "StatusService" });
    this.statusCache = {}; // Cache em memória para o estado mais recente
  }

  async runAllChecks() {
    this.logger.info("Iniciando ciclo de verificação de todos os serviços.");
    const checks = Object.entries(this.servicesConfig).map(([id, config]) =>
      this.checkService(id, config)
    );
    await Promise.all(checks);
    this.logger.info("Ciclo de verificação concluído.");
  }

  async checkService(id, config) {
    const checker = this.getCheckerForService(id, config);
    try {
      const result = await checker.check();
      this.statusCache[id] = result;
      this.sseService.sendToAll(result);
      this.logger.info(
        { serviceId: id, status: result.status },
        "Serviço verificado."
      );
    } catch (error) {
      this.logger.error(
        { err: error, serviceId: id },
        "Falha ao verificar serviço."
      );
      const errorResult = {
        id,
        name: config.name,
        status: "MAJOR_OUTAGE",
        error: error.message,
        lastChecked: new Date().toISOString(),
      };
      this.statusCache[id] = errorResult;
      this.sseService.sendToAll(errorResult);
    }
  }

  getCheckerForService(id, config) {
    switch (config.checkType) {
      case "statuspage":
        return new StatusPageChecker(id, config);
      case "http":
        return new HttpChecker(id, config);
      default:
        throw new Error(
          `Tipo de verificador desconhecido: ${config.checkType}`
        );
    }
  }

  getInitialStatus() {
    return Object.values(this.statusCache);
  }
}

// ===================================================================================
// 4. CONTROLLER E ROTAS
// ===================================================================================
class StatusController {
  constructor(statusService, sseService) {
    this.statusService = statusService;
    this.sseService = sseService;
  }

  handleSse = (req, res) => {
    const clientId = this.sseService.addClient(res);
    const initialState = {
      type: "initial_state",
      payload: this.statusService.getInitialStatus(),
    };
    this.sseService.sendToOne(clientId, initialState);
  };

  getMyInfo = async (req, res, next) => {
    try {
      const ip = req.ip;
      if (ip === "::1" || ip === "127.0.0.1") {
        return res.json({ ip: "127.0.0.1", isp: "Localhost" });
      }
      const geoResponse = await fetch(
        `http://ip-api.com/json/${ip}?fields=query,isp`
      );
      if (!geoResponse.ok)
        throw new Error("Falha ao obter dados de geolocalização.");

      const geoData = await geoResponse.json();
      res.json({ ip: geoData.query, isp: geoData.isp || "Não identificada" });
    } catch (error) {
      next(error); // Passa o erro para o handler global
    }
  };
}

class ApiRoutes {
  constructor(statusController) {
    this.router = express.Router();
    this.controller = statusController;
    this.initializeRoutes();
  }

  initializeRoutes() {
    this.router.get("/status-stream", this.controller.handleSse);
    this.router.get("/my-info", this.controller.getMyInfo);
  }

  getRouter() {
    return this.router;
  }
}

// ===================================================================================
// 5. CLASSE PRINCIPAL DA APLICAÇÃO EXPRESS
// ===================================================================================
class App {
  constructor(apiRouter, logger) {
    this.app = express();
    this.logger = logger;
    this.setupMiddlewares();
    this.setupRoutes(apiRouter);
    this.setupErrorHandlers();
  }

  setupMiddlewares() {
    this.app.use(cors());
    this.app.use(express.json());
    this.app.set("trust proxy", true);
  }

  setupRoutes(apiRouter) {
    this.app.get("/", (req, res) =>
      res.json({ message: "Servidor do Painel de Status está operando!" })
    );
    this.app.use("/api", apiRouter);
  }

  setupErrorHandlers() {
    this.app.use((req, res, next) => {
      res.status(404).json({ error: "Rota não encontrada" });
    });
    this.app.use((err, req, res, next) => {
      this.logger.error({ err }, "Ocorreu um erro não tratado no servidor");
      res.status(500).json({ error: "Ocorreu um erro interno no servidor." });
    });
  }

  getApp() {
    return this.app;
  }
}

// ===================================================================================
// 6. PONTO DE ENTRADA (MAIN)
// ===================================================================================
async function main() {
  const logger = pino({ level: "info" });

  try {
    // --- Injeção de Dependências Simplificada ---
    const sseService = new SseService(logger);
    const statusService = new StatusService(
      Config.services,
      sseService,
      logger
    );
    const statusController = new StatusController(statusService, sseService);
    const apiRoutes = new ApiRoutes(statusController).getRouter();
    const appInstance = new App(apiRoutes, logger);
    const expressApp = appInstance.getApp();

    // --- Inicialização do Servidor e Loop ---
    const PORT = process.env.PORT || 3000;
    expressApp.listen(PORT, () => {
      logger.info(`Servidor rodando na porta ${PORT}`);
      logger.info("Iniciando a primeira verificação de todos os serviços...");
      statusService.runAllChecks();
      setInterval(() => statusService.runAllChecks(), Config.CHECK_INTERVAL);
    });
  } catch (error) {
    logger.fatal({ err: error }, "Falha fatal ao inicializar a aplicação.");
    process.exit(1);
  }
}

main();
