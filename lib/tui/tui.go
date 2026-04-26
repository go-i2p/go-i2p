// Package tui provides a text-based user interface for the go-i2p router.
package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/go-i2p/i2ptui"
)

// WrapperModel wraps the i2ptui Model and adds a password reveal panel
// so that other applications can discover the I2PControl credentials.
type WrapperModel struct {
	inner         i2ptui.Model
	password      string
	address       string
	showPassword  bool
	width, height int
}

// New creates a WrapperModel that embeds the i2ptui TUI with the given options
// and stores the password/address for the reveal panel.
func New(password, address string, opts ...i2ptui.Option) WrapperModel {
	return WrapperModel{
		inner:    i2ptui.New(opts...),
		password: password,
		address:  address,
	}
}

// Init implements tea.Model.
func (m WrapperModel) Init() tea.Cmd {
	return m.inner.Init()
}

// Update implements tea.Model.
func (m WrapperModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	case tea.KeyMsg:
		if m.showPassword {
			// Any key dismisses the password panel
			if msg.String() == "esc" || msg.String() == "p" || msg.String() == "enter" {
				m.showPassword = false
				return m, nil
			}
			return m, nil
		}
		if msg.String() == "p" {
			m.showPassword = true
			return m, nil
		}
	}

	updated, cmd := m.inner.Update(msg)
	if model, ok := updated.(i2ptui.Model); ok {
		m.inner = model
	}
	return m, cmd
}

// View implements tea.Model.
func (m WrapperModel) View() string {
	base := m.inner.View()
	if !m.showPassword {
		return base
	}
	return base + "\n" + m.renderPasswordPanel()
}

var (
	panelBorder = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("214")).
			Padding(1, 2)

	panelTitle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("214"))

	panelLabel = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("252"))

	panelValue = lipgloss.NewStyle().
			Foreground(lipgloss.Color("120"))
)

func (m WrapperModel) renderPasswordPanel() string {
	var b strings.Builder
	b.WriteString(panelTitle.Render("I2PControl Credentials"))
	b.WriteString("\n\n")
	fmt.Fprintf(&b, "  %s %s\n", panelLabel.Render("Address: "), panelValue.Render(m.address))
	fmt.Fprintf(&b, "  %s %s\n", panelLabel.Render("Password:"), panelValue.Render(m.password))
	b.WriteString("\n")
	b.WriteString("  Use these credentials to connect other I2P\n")
	b.WriteString("  applications to this router's I2PControl API.\n\n")
	b.WriteString("  Press [p] or [Esc] to dismiss")

	content := b.String()
	return panelBorder.Render(content)
}
