declare module "react-cytoscapejs" {
  import type { CSSProperties, ComponentType } from "react";
  import type cytoscape from "cytoscape";

  interface CytoscapeStylesheet {
    selector: string;
    style: Record<string, string | number>;
  }

  interface CytoscapeComponentProps {
    elements?: cytoscape.ElementDefinition[];
    stylesheet?: CytoscapeStylesheet[];
    layout?: cytoscape.LayoutOptions;
    style?: CSSProperties;
    className?: string;
    cy?: (cy: cytoscape.Core) => void;
    wheelSensitivity?: number;
    minZoom?: number;
    maxZoom?: number;
    boxSelectionEnabled?: boolean;
    autounselectify?: boolean;
    panningEnabled?: boolean;
    userPanningEnabled?: boolean;
    zoomingEnabled?: boolean;
    userZoomingEnabled?: boolean;
    autoungrabify?: boolean;
    selectionType?: "single" | "additive";
  }

  const CytoscapeComponent: ComponentType<CytoscapeComponentProps>;

  export default CytoscapeComponent;
}
