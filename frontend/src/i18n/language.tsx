import {
  createContext,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from "react";

export type Language = "es" | "en";

const translations: Record<
  Language,
  Record<string, string>
> = {
  es: {
    // MENÚ
    "menu.dashboard": "Dashboard",
    "menu.sites": "Sitios web",
    "menu.scans": "Escaneos",
    "menu.findings": "Hallazgos",
    "menu.reports": "Reportes",
    "menu.settings": "Configuración",
    "menu.back": "Volver",

    // BIENVENIDA
    "welcome.subtitle": "Análisis de seguridad web",
    "welcome.description":
      "Identifica vulnerabilidades, evalúa riesgos y genera reportes de seguridad sobre sitios web autorizados mediante distintos módulos de análisis.",
    "welcome.enter": "Entrar a VulnHunter →",
    "welcome.analysis": "Análisis de vulnerabilidades",
    "welcome.analysisText":
      "Revisa distintos aspectos de seguridad de un sitio web.",
    "welcome.risk": "Evaluación de riesgos",
    "welcome.riskText":
      "Clasifica los hallazgos según su nivel de severidad.",
    "welcome.reports": "Reportes de seguridad",
    "welcome.reportsText":
      "Genera reportes con hallazgos y recomendaciones de mitigación.",
    "welcome.warning":
      "VulnHunter debe utilizarse únicamente sobre sistemas propios o expresamente autorizados.",

    // CONFIGURACIÓN
    "settings.title": "Configuración",
    "settings.description":
      "Personaliza las preferencias generales de VulnHunter.",
    "settings.general": "General",
    "settings.language": "Idioma",
    "settings.spanish": "Español",
    "settings.english": "Inglés",
    "settings.theme": "Tema",
    "settings.dark": "Oscuro",

    "settings.scans": "Preferencias de escaneo",
    "settings.scanDescription":
      "Configura los módulos que se utilizarán por defecto en los análisis.",

    "settings.ssl": "SSL/TLS",
    "settings.xss": "XSS",
    "settings.sqli": "Inyección SQL",
    "settings.headers": "Headers de seguridad",
    "settings.directories": "Directorios expuestos",

    "settings.reports": "Reportes",
    "settings.evidence": "Incluir evidencias",
    "settings.recommendations": "Incluir recomendaciones",
    "settings.risk": "Incluir nivel de riesgo",

    "settings.about": "Acerca de VulnHunter",
    "settings.version": "Versión",
  },

  en: {
    // MENU
    "menu.dashboard": "Dashboard",
    "menu.sites": "Websites",
    "menu.scans": "Scans",
    "menu.findings": "Findings",
    "menu.reports": "Reports",
    "menu.settings": "Settings",
    "menu.back": "Back",

    // WELCOME
    "welcome.subtitle": "Web security analysis",
    "welcome.description":
      "Identify vulnerabilities, assess risks, and generate security reports for authorized websites using different analysis modules.",
    "welcome.enter": "Enter VulnHunter →",
    "welcome.analysis": "Vulnerability analysis",
    "welcome.analysisText":
      "Review different security aspects of a website.",
    "welcome.risk": "Risk assessment",
    "welcome.riskText":
      "Classify findings according to their severity level.",
    "welcome.reports": "Security reports",
    "welcome.reportsText":
      "Generate reports with findings and mitigation recommendations.",
    "welcome.warning":
      "VulnHunter must only be used on systems you own or are explicitly authorized to test.",

    // SETTINGS
    "settings.title": "Settings",
    "settings.description":
      "Customize VulnHunter's general preferences.",
    "settings.general": "General",
    "settings.language": "Language",
    "settings.spanish": "Spanish",
    "settings.english": "English",
    "settings.theme": "Theme",
    "settings.dark": "Dark",

    "settings.scans": "Scan preferences",
    "settings.scanDescription":
      "Configure the modules used by default during scans.",

    "settings.ssl": "SSL/TLS",
    "settings.xss": "XSS",
    "settings.sqli": "SQL Injection",
    "settings.headers": "Security headers",
    "settings.directories": "Exposed directories",

    "settings.reports": "Reports",
    "settings.evidence": "Include evidence",
    "settings.recommendations": "Include recommendations",
    "settings.risk": "Include risk level",

    "settings.about": "About VulnHunter",
    "settings.version": "Version",
  },
};

type LanguageContextType = {
  language: Language;
  setLanguage: (language: Language) => void;
  t: (key: string) => string;
};

const LanguageContext =
  createContext<LanguageContextType | undefined>(
    undefined
  );

export function LanguageProvider({
  children,
}: {
  children: ReactNode;
}) {
  const [language, setLanguage] =
    useState<Language>(() => {
      const savedLanguage = localStorage.getItem(
        "vulnhunter-language"
      );

      return savedLanguage === "en"
        ? "en"
        : "es";
    });

  useEffect(() => {
    localStorage.setItem(
      "vulnhunter-language",
      language
    );

    document.documentElement.lang = language;
  }, [language]);

  const t = (key: string) => {
    return translations[language][key] ?? key;
  };

  return (
    <LanguageContext.Provider
      value={{
        language,
        setLanguage,
        t,
      }}
    >
      {children}
    </LanguageContext.Provider>
  );
}

export function useLanguage() {
  const context = useContext(LanguageContext);

  if (!context) {
    throw new Error(
      "useLanguage debe utilizarse dentro de LanguageProvider"
    );
  }

  return context;
}