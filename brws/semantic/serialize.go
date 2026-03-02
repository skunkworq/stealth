package semantic

import (
	"fmt"
	"strings"
)

type CollapsedPage struct {
	URL            string
	Domain         string
	Summary        string
	OriginalTokens uint32
}

func SerializeTree(tree *SemanticTree, state *UnfoldState, collapsedPages []CollapsedPage) string {
	var out strings.Builder

	out.WriteString("[WEBFURL]\n")

	for _, page := range collapsedPages {
		out.WriteString(fmt.Sprintf("[previously: %s - %s] (%d tokens saved)\n", page.Domain, page.Summary, page.OriginalTokens))
	}

	out.WriteString(fmt.Sprintf("[current: %s]\n", tree.URL))

	for i := range tree.RootNodes {
		serializeNode(&out, &tree.RootNodes[i], state, 1)
	}

	out.WriteString("[/WEBFURL]")
	return out.String()
}

func serializeNode(out *strings.Builder, node *SemanticNode, state *UnfoldState, depth int) {
	indent := strings.Repeat("  ", depth)

	line := fmt.Sprintf("%s[%s]", indent, node.Summary)
	line += fmt.Sprintf(" {#%s}", node.ID)

	if len(node.Actions) == 1 {
		tag := actionTypeToShort(&node.Actions[0])
		line += fmt.Sprintf(" (%s)", tag)
	} else if len(node.Actions) > 1 {
		types := make(map[string]bool)
		for i := range node.Actions {
			types[actionTypeToShort(&node.Actions[i])] = true
		}
		var typeList []string
		for t := range types {
			typeList = append(typeList, t)
		}
		line += fmt.Sprintf(" (%s)", strings.Join(typeList, ", "))
	}

	out.WriteString(line)
	out.WriteString("\n")

	if len(node.Images) > 0 {
		var described []string
		var undescribed int
		for i := range node.Images {
			if node.Images[i].Description != "" {
				described = append(described, node.Images[i].Description)
			} else {
				undescribed++
			}
		}

		for _, desc := range described {
			fmt.Fprintf(out, "%s  [img: %s]\n", indent, desc)
		}
		if undescribed > 0 {
			plural := ""
			if undescribed > 1 {
				plural = "s"
			}
			fmt.Fprintf(out, "%s  [%d image%s — use describe #%s to inspect]\n", indent, undescribed, plural, node.ID)
		}
	}

	isUnfolded := false
	for _, id := range state.Unfolded {
		if id == node.ID {
			isUnfolded = true
			break
		}
	}

	if isUnfolded && len(node.Children) > 0 {
		for i := range node.Children {
			serializeNode(out, &node.Children[i], state, depth+1)
		}
	} else if len(node.Children) > 0 {
		childCount := len(node.Children)
		extraTokens := node.UnfoldCost()
		fmt.Fprintf(out, "%s  ... (%d children, +%d tokens to unfold)\n", indent, childCount, extraTokens)
	}

	if len(node.Children) == 0 && node.RawText != "" {
		if isUnfolded {
			fmt.Fprintf(out, "%s  [raw] %s\n", indent, node.RawText)
		} else if node.RawTextTokens > 0 {
			fmt.Fprintf(out, "%s  ... (raw text, +%d tokens to unfold)\n", indent, node.RawTextTokens)
		}
	}
}

func actionTypeToShort(a *Action) string {
	switch a.Type {
	case ActionClick:
		return "clickable"
	case ActionFill:
		return "fillable"
	case ActionSelect:
		return "selectable"
	case ActionToggle:
		return "toggleable"
	default:
		return "interactive"
	}
}

func CollapseTree(tree *SemanticTree, interactionSummary string) CollapsedPage {
	var topLevel []string
	for i := range tree.RootNodes {
		topLevel = append(topLevel, tree.RootNodes[i].Summary)
	}

	var summary string
	if interactionSummary == "" {
		summary = fmt.Sprintf("Visited. Sections: %s", strings.Join(topLevel, ", "))
	} else {
		summary = fmt.Sprintf("%s. Sections: %s", interactionSummary, strings.Join(topLevel, ", "))
	}

	return CollapsedPage{
		URL:            tree.URL,
		Domain:         tree.Domain,
		Summary:        summary,
		OriginalTokens: tree.FullTokenCount,
	}
}
