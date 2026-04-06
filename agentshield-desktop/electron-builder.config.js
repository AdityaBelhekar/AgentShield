module.exports = {
  appId: "dev.agentshield.desktop",
  productName: "AgentShield",
  directories: { output: "release" },
  files: ["dist/**/*", "electron/**/*.js", "resources/**/*"],
  mac:   { target: "dmg", icon: "resources/icon.png" },
  win:   { target: "nsis", icon: "resources/icon.png" },
  linux: { target: "AppImage", icon: "resources/icon.png" },
  extraResources: [
    { from: "resources/venv", to: "venv", filter: ["**/*"] }
  ]
}
