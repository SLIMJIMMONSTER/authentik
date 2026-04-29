import "#elements/EmptyState";

import { DEFAULT_CONFIG } from "#common/api/config";

import { Diagram } from "#elements/Diagram";

import { FlowsApi } from "@goauthentik/api";

import { PropertyValues } from "lit-element/lit-element.js";
import { customElement, property } from "lit/decorators.js";

@customElement("ak-flow-diagram")
export class FlowDiagram extends Diagram {
    @property({ type: String, useDefault: true })
    flowSlug: string | null = null;

    protected override updated(changedProperties: PropertyValues<this>): void {
        super.updated(changedProperties);

        if (changedProperties.has("flowSlug")) {
            this.refresh();
        }
    }

    protected refresh = (): void => {
        new FlowsApi(DEFAULT_CONFIG)
            .flowsInstancesDiagramRetrieve({
                slug: this.flowSlug || "",
            })
            .then((data) => {
                this.diagram = data.diagram;
            });
    };
}

declare global {
    interface HTMLElementTagNameMap {
        "ak-flow-diagram": FlowDiagram;
    }
}
