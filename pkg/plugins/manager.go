package plugins

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"plugin"
	"strings"
	"time"

	"github.com/thechosenone-shall-prevail/KERB-SLEUTH/pkg/krb"
)

// PluginInterface defines the interface that plugins must implement
type PluginInterface interface {
	GetName() string
	GetVersion() string
	GetDescription() string
	GetAuthor() string
	Initialize(config map[string]interface{}) error
	Execute(input map[string]interface{}) (map[string]interface{}, error)
	Cleanup() error
}

// PluginInfo represents plugin metadata
type PluginInfo struct {
	Name        string                 `json:"name"`
	Version     string                 `json:"version"`
	Description string                 `json:"description"`
	Author      string                 `json:"author"`
	License     string                 `json:"license"`
	Homepage    string                 `json:"homepage"`
	Tags        []string               `json:"tags"`
	Config      map[string]interface{} `json:"config"`
	Enabled     bool                   `json:"enabled"`
	LoadedAt    time.Time              `json:"loaded_at"`
}

// PluginResult represents plugin execution results
type PluginResult struct {
	PluginName string                 `json:"plugin_name"`
	Success    bool                   `json:"success"`
	Output     map[string]interface{} `json:"output"`
	Error      string                 `json:"error"`
	Duration   time.Duration          `json:"duration"`
	Timestamp  time.Time              `json:"timestamp"`
}

// PluginManager manages plugins
type PluginManager struct {
	Plugins        map[string]*LoadedPlugin
	PluginDir      string
	ConfigFile     string
	EnabledPlugins []string
}

// LoadedPlugin represents a loaded plugin
type LoadedPlugin struct {
	Info     *PluginInfo
	Instance PluginInterface
	Plugin   *plugin.Plugin
	Path     string
}

// NewPluginManager creates a new plugin manager
func NewPluginManager(pluginDir, configFile string) *PluginManager {
	return &PluginManager{
		Plugins:        make(map[string]*LoadedPlugin),
		PluginDir:      pluginDir,
		ConfigFile:     configFile,
		EnabledPlugins: []string{},
	}
}

// LoadPlugins loads all available plugins
func (pm *PluginManager) LoadPlugins() error {
	log.Printf("🔌 Loading plugins from: %s", pm.PluginDir)

	// Create plugin directory if it doesn't exist
	if err := os.MkdirAll(pm.PluginDir, 0755); err != nil {
		return fmt.Errorf("failed to create plugin directory: %v", err)
	}

	// Load plugin configuration
	if err := pm.loadPluginConfig(); err != nil {
		log.Printf("⚠️  Failed to load plugin config: %v", err)
	}

	// Find all plugin files
	pluginFiles, err := filepath.Glob(filepath.Join(pm.PluginDir, "*.so"))
	if err != nil {
		return fmt.Errorf("failed to find plugin files: %v", err)
	}

	// Load each plugin
	for _, pluginFile := range pluginFiles {
		if err := pm.loadPlugin(pluginFile); err != nil {
			log.Printf("⚠️  Failed to load plugin %s: %v", pluginFile, err)
			continue
		}
	}

	log.Printf("✅ Loaded %d plugins", len(pm.Plugins))
	return nil
}

// loadPlugin loads a single plugin
func (pm *PluginManager) loadPlugin(pluginPath string) error {
	log.Printf("🔌 Loading plugin: %s", pluginPath)

	// Open plugin
	p, err := plugin.Open(pluginPath)
	if err != nil {
		return fmt.Errorf("failed to open plugin: %v", err)
	}

	// Look up the plugin interface
	symbol, err := p.Lookup("Plugin")
	if err != nil {
		return fmt.Errorf("failed to lookup Plugin symbol: %v", err)
	}

	// Cast to plugin interface
	pluginInstance, ok := symbol.(PluginInterface)
	if !ok {
		return fmt.Errorf("plugin does not implement PluginInterface")
	}

	// Get plugin info
	name := pluginInstance.GetName()
	version := pluginInstance.GetVersion()
	description := pluginInstance.GetDescription()
	author := pluginInstance.GetAuthor()

	// Check if plugin is enabled
	enabled := pm.isPluginEnabled(name)

	pluginInfo := &PluginInfo{
		Name:        name,
		Version:     version,
		Description: description,
		Author:      author,
		Enabled:     enabled,
		LoadedAt:    time.Now(),
	}

	// Initialize plugin if enabled
	if enabled {
		if err := pluginInstance.Initialize(map[string]interface{}{}); err != nil {
			return fmt.Errorf("failed to initialize plugin: %v", err)
		}
		log.Printf("✅ Plugin %s v%s initialized", name, version)
	} else {
		log.Printf("⚠️  Plugin %s v%s disabled", name, version)
	}

	// Store loaded plugin
	pm.Plugins[name] = &LoadedPlugin{
		Info:     pluginInfo,
		Instance: pluginInstance,
		Plugin:   p,
		Path:     pluginPath,
	}

	return nil
}

// ExecutePlugin executes a specific plugin
func (pm *PluginManager) ExecutePlugin(pluginName string, input map[string]interface{}) (*PluginResult, error) {
	loadedPlugin, exists := pm.Plugins[pluginName]
	if !exists {
		return nil, fmt.Errorf("plugin %s not found", pluginName)
	}

	if !loadedPlugin.Info.Enabled {
		return nil, fmt.Errorf("plugin %s is disabled", pluginName)
	}

	log.Printf("🔌 Executing plugin: %s", pluginName)

	startTime := time.Now()
	output, err := loadedPlugin.Instance.Execute(input)
	duration := time.Since(startTime)

	result := &PluginResult{
		PluginName: pluginName,
		Success:    err == nil,
		Output:     output,
		Duration:   duration,
		Timestamp:  time.Now(),
	}

	if err != nil {
		result.Error = err.Error()
		log.Printf("⚠️  Plugin %s execution failed: %v", pluginName, err)
	} else {
		log.Printf("✅ Plugin %s executed successfully in %v", pluginName, duration)
	}

	return result, nil
}

// ExecuteAllPlugins executes all enabled plugins
func (pm *PluginManager) ExecuteAllPlugins(input map[string]interface{}) ([]*PluginResult, error) {
	log.Printf("🔌 Executing all enabled plugins...")

	results := []*PluginResult{}

	for name, loadedPlugin := range pm.Plugins {
		if !loadedPlugin.Info.Enabled {
			continue
		}

		result, err := pm.ExecutePlugin(name, input)
		if err != nil {
			log.Printf("⚠️  Failed to execute plugin %s: %v", name, err)
			continue
		}

		results = append(results, result)
	}

	log.Printf("✅ Executed %d plugins", len(results))
	return results, nil
}

// EnablePlugin enables a plugin
func (pm *PluginManager) EnablePlugin(pluginName string) error {
	loadedPlugin, exists := pm.Plugins[pluginName]
	if !exists {
		return fmt.Errorf("plugin %s not found", pluginName)
	}

	if loadedPlugin.Info.Enabled {
		return fmt.Errorf("plugin %s is already enabled", pluginName)
	}

	// Initialize plugin
	if err := loadedPlugin.Instance.Initialize(map[string]interface{}{}); err != nil {
		return fmt.Errorf("failed to initialize plugin: %v", err)
	}

	loadedPlugin.Info.Enabled = true
	pm.EnabledPlugins = append(pm.EnabledPlugins, pluginName)

	log.Printf("✅ Plugin %s enabled", pluginName)
	return nil
}

// DisablePlugin disables a plugin
func (pm *PluginManager) DisablePlugin(pluginName string) error {
	loadedPlugin, exists := pm.Plugins[pluginName]
	if !exists {
		return fmt.Errorf("plugin %s not found", pluginName)
	}

	if !loadedPlugin.Info.Enabled {
		return fmt.Errorf("plugin %s is already disabled", pluginName)
	}

	// Cleanup plugin
	if err := loadedPlugin.Instance.Cleanup(); err != nil {
		log.Printf("⚠️  Failed to cleanup plugin %s: %v", pluginName, err)
	}

	loadedPlugin.Info.Enabled = false
	pm.removeFromEnabledList(pluginName)

	log.Printf("✅ Plugin %s disabled", pluginName)
	return nil
}

// UnloadPlugin unloads a plugin
func (pm *PluginManager) UnloadPlugin(pluginName string) error {
	loadedPlugin, exists := pm.Plugins[pluginName]
	if !exists {
		return fmt.Errorf("plugin %s not found", pluginName)
	}

	// Cleanup and disable
	if loadedPlugin.Info.Enabled {
		if err := pm.DisablePlugin(pluginName); err != nil {
			log.Printf("⚠️  Failed to disable plugin %s: %v", pluginName, err)
		}
	}

	// Remove from plugins map
	delete(pm.Plugins, pluginName)

	log.Printf("✅ Plugin %s unloaded", pluginName)
	return nil
}

// ListPlugins returns information about all loaded plugins
func (pm *PluginManager) ListPlugins() []*PluginInfo {
	plugins := make([]*PluginInfo, 0, len(pm.Plugins))
	for _, loadedPlugin := range pm.Plugins {
		plugins = append(plugins, loadedPlugin.Info)
	}
	return plugins
}

// GetPluginInfo returns information about a specific plugin
func (pm *PluginManager) GetPluginInfo(pluginName string) (*PluginInfo, error) {
	loadedPlugin, exists := pm.Plugins[pluginName]
	if !exists {
		return nil, fmt.Errorf("plugin %s not found", pluginName)
	}
	return loadedPlugin.Info, nil
}

// Helper functions

func (pm *PluginManager) isPluginEnabled(pluginName string) bool {
	for _, enabled := range pm.EnabledPlugins {
		if enabled == pluginName {
			return true
		}
	}
	return false
}

func (pm *PluginManager) removeFromEnabledList(pluginName string) {
	for i, enabled := range pm.EnabledPlugins {
		if enabled == pluginName {
			pm.EnabledPlugins = append(pm.EnabledPlugins[:i], pm.EnabledPlugins[i+1:]...)
			break
		}
	}
}

func (pm *PluginManager) loadPluginConfig() error {
	if _, err := os.Stat(pm.ConfigFile); os.IsNotExist(err) {
		// Create default config
		config := map[string]interface{}{
			"enabled_plugins": []string{},
		}
		return pm.savePluginConfig(config)
	}

	data, err := os.ReadFile(pm.ConfigFile)
	if err != nil {
		return fmt.Errorf("failed to read config file: %v", err)
	}

	var config map[string]interface{}
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse config file: %v", err)
	}

	// Load enabled plugins
	if enabledPlugins, ok := config["enabled_plugins"].([]interface{}); ok {
		pm.EnabledPlugins = make([]string, len(enabledPlugins))
		for i, plugin := range enabledPlugins {
			if pluginName, ok := plugin.(string); ok {
				pm.EnabledPlugins[i] = pluginName
			}
		}
	}

	return nil
}

func (pm *PluginManager) savePluginConfig(config map[string]interface{}) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %v", err)
	}

	return os.WriteFile(pm.ConfigFile, data, 0644)
}

// SavePluginConfig saves the current plugin configuration
func (pm *PluginManager) SavePluginConfig() error {
	config := map[string]interface{}{
		"enabled_plugins": pm.EnabledPlugins,
	}
	return pm.savePluginConfig(config)
}

// IntegrateWithKerberosAnalysis integrates plugins with Kerberos analysis
func (pm *PluginManager) IntegrateWithKerberosAnalysis(results []krb.Candidate) error {
	log.Printf("🔌 Integrating plugins with Kerberos analysis...")

	// Prepare input for plugins
	input := map[string]interface{}{
		"kerberos_results": results,
		"analysis_type":    "kerberos",
		"timestamp":        time.Now(),
	}

	// Execute all enabled plugins
	pluginResults, err := pm.ExecuteAllPlugins(input)
	if err != nil {
		return fmt.Errorf("failed to execute plugins: %v", err)
	}

	// Process plugin results
	for _, result := range pluginResults {
		if result.Success {
			log.Printf("✅ Plugin %s processed %d Kerberos results", result.PluginName, len(results))
		} else {
			log.Printf("⚠️  Plugin %s failed: %s", result.PluginName, result.Error)
		}
	}

	log.Printf("✅ Plugin integration completed")
	return nil
}

// CreatePluginTemplate creates a plugin template
func CreatePluginTemplate(pluginName, author, description string) error {
	log.Printf("📝 Creating plugin template: %s", pluginName)

	// Create plugin directory
	pluginDir := fmt.Sprintf("plugins/%s", pluginName)
	if err := os.MkdirAll(pluginDir, 0755); err != nil {
		return fmt.Errorf("failed to create plugin directory: %v", err)
	}

	// Create main plugin file
	pluginCode := fmt.Sprintf(`package main

import (
	"fmt"
	"log"
	"time"
)

// %sPlugin implements the PluginInterface
type %sPlugin struct {
	name        string
	version     string
	description string
	author      string
	initialized bool
}

// New%sPlugin creates a new plugin instance
func New%sPlugin() *%sPlugin {
	return &%sPlugin{
		name:        "%s",
		version:     "1.0.0",
		description: "%s",
		author:      "%s",
		initialized: false,
	}
}

// GetName returns the plugin name
func (p *%sPlugin) GetName() string {
	return p.name
}

// GetVersion returns the plugin version
func (p *%sPlugin) GetVersion() string {
	return p.version
}

// GetDescription returns the plugin description
func (p *%sPlugin) GetDescription() string {
	return p.description
}

// GetAuthor returns the plugin author
func (p *%sPlugin) GetAuthor() string {
	return p.author
}

// Initialize initializes the plugin
func (p *%sPlugin) Initialize(config map[string]interface{}) error {
	log.Printf("Initializing plugin: %%s", p.name)
	p.initialized = true
	return nil
}

// Execute executes the plugin
func (p *%sPlugin) Execute(input map[string]interface{}) (map[string]interface{}, error) {
	if !p.initialized {
		return nil, fmt.Errorf("plugin not initialized")
	}

	log.Printf("Executing plugin: %%s", p.name)

	// Process input
	results := map[string]interface{}{
		"plugin_name": p.name,
		"timestamp":   time.Now(),
		"processed":   true,
	}

	// Add your plugin logic here
	// Example: process Kerberos results
	if kerberosResults, ok := input["kerberos_results"]; ok {
		results["kerberos_count"] = len(kerberosResults.([]interface{}))
	}

	return results, nil
}

// Cleanup cleans up the plugin
func (p *%sPlugin) Cleanup() error {
	log.Printf("Cleaning up plugin: %%s", p.name)
	p.initialized = false
	return nil
}

// Plugin is the exported plugin instance
var Plugin = New%sPlugin()
`,
		strings.Title(pluginName), // %sPlugin struct name
		strings.Title(pluginName), // %sPlugin struct name
		strings.Title(pluginName), // New%sPlugin function
		strings.Title(pluginName), // New%sPlugin return type
		strings.Title(pluginName), // *%sPlugin return type
		strings.Title(pluginName), // &%sPlugin constructor
		pluginName,                // name field value
		description,               // description field value
		author,                    // author field value
		strings.Title(pluginName), // GetName %sPlugin receiver
		strings.Title(pluginName), // GetVersion %sPlugin receiver
		strings.Title(pluginName), // GetDescription %sPlugin receiver
		strings.Title(pluginName), // GetAuthor %sPlugin receiver
		strings.Title(pluginName), // Initialize %sPlugin receiver
		strings.Title(pluginName), // Execute %sPlugin receiver
		strings.Title(pluginName), // Cleanup %sPlugin receiver
		strings.Title(pluginName), // New%sPlugin in var Plugin
	)

	err := os.WriteFile(filepath.Join(pluginDir, "main.go"), []byte(pluginCode), 0644)
	if err != nil {
		return fmt.Errorf("failed to create plugin main.go: %v", err)
	}

	// Create go.mod file
	goMod := fmt.Sprintf(`module %s

go 1.21

require (
	github.com/thechosenone-shall-prevail/KERB-SLEUTH/pkg/krb v0.0.0
)

replace github.com/thechosenone-shall-prevail/KERB-SLEUTH/pkg/krb => ../../pkg/krb
`, pluginName)

	err = os.WriteFile(filepath.Join(pluginDir, "go.mod"), []byte(goMod), 0644)
	if err != nil {
		return fmt.Errorf("failed to create go.mod: %v", err)
	}

	// Create README.md
	readme := fmt.Sprintf(`# %s Plugin

%s

## Author
%s

## Installation
1. Build the plugin:
   `+"```bash"+`
   cd %s
   go build -buildmode=plugin -o %s.so main.go
   `+"```"+`

2. Copy the plugin to the KERB-SLEUTH plugins directory:
   `+"```bash"+`
   cp %s.so /path/to/kerb-sleuth/plugins/
   `+"```"+`

3. Enable the plugin in KERB-SLEUTH configuration

## Usage
This plugin will be automatically executed during Kerberos analysis.

## Configuration
No special configuration required.
`, pluginName, description, author, pluginName, pluginName, pluginName)

	err = os.WriteFile(filepath.Join(pluginDir, "README.md"), []byte(readme), 0644)
	if err != nil {
		return fmt.Errorf("failed to create README.md: %v", err)
	}

	// Create build script
	buildScript := fmt.Sprintf(`#!/bin/bash
echo "Building %s plugin..."
go build -buildmode=plugin -o %s.so main.go
echo "Plugin built successfully: %s.so"
`, pluginName, pluginName, pluginName)

	err = os.WriteFile(filepath.Join(pluginDir, "build.sh"), []byte(buildScript), 0755)
	if err != nil {
		return fmt.Errorf("failed to create build script: %v", err)
	}

	log.Printf("✅ Plugin template created in: %s", pluginDir)
	return nil
}
