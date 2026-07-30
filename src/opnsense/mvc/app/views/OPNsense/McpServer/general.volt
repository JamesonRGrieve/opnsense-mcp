{#
 # SPDX-License-Identifier: BSD-2-Clause
 #
 # Copyright (c) 2026 Jameson Grieve <jamesonrgrieve@gmail.com>
 # All rights reserved.
 #
 # Redistribution and use in source and binary forms, with or without modification,
 # are permitted provided that the following conditions are met:
 #
 # 1. Redistributions of source code must retain the above copyright notice,
 #    this list of conditions and the following disclaimer.
 #
 # 2. Redistributions in binary form must reproduce the above copyright notice,
 #    this list of conditions and the following disclaimer in the documentation
 #    and/or other materials provided with the distribution.
 #
 # THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 # INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 # AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 # AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 # OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 # SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 # INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 # CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 # ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 # POSSIBILITY OF SUCH DAMAGE.
 #}

<script>
    $(document).ready(function () {
        mapDataToFormUI({'frm_GeneralSettings': '/api/mcpserver/general/get'}).done(function () {
            formatTokenRecords();
        });

        $("#saveAct").SimpleActionButton({
            onPreAction: function () {
                const dfObj = new $.Deferred();
                saveFormToEndpoint('/api/mcpserver/general/set', 'frm_GeneralSettings', function () {
                    dfObj.resolve();
                });
                return dfObj;
            },
            onAction: function (data, status) {
                updateServiceControlUI('mcpserver');
            }
        });

        updateServiceControlUI('mcpserver');
    });
</script>

<div class="content-box" style="padding: 10px;">
    <div class="col-md-12">
        <div class="alert alert-info" role="alert" style="min-height: 65px;">
            <p>
                <strong>{{ lang._('MCP Server') }}</strong><br/>
                {{ lang._('Read-only Model Context Protocol server for AI-assisted firewall inspection. No write operations — all tools are read-only by design.') }}
            </p>
        </div>
    </div>
</div>

<div id="frm_GeneralSettings">
    {{ partial("layout_partials/base_form", ['fields': generalForm, 'id': 'frm_GeneralSettings']) }}
</div>

<div class="col-md-12">
    <button class="btn btn-primary" id="saveAct"
            data-endpoint="/api/mcpserver/service/reconfigure"
            data-label="{{ lang._('Apply') }}"
            data-error-title="{{ lang._('Error reconfiguring MCP Server') }}"
            type="button">
    </button>
</div>

<div class="col-md-12" style="margin-top: 20px;">
    <h3>{{ lang._('Service') }}</h3>
    {{ partial("layout_partials/service_control", ['serviceName': 'mcpserver']) }}
</div>

<div class="col-md-12" style="margin-top: 20px;">
    <h3>{{ lang._('Client Configuration') }}</h3>
    <div class="alert alert-info">
        <p>{{ lang._('To connect Claude Code to this MCP server:') }}</p>
        <pre>claude mcp add opnsense --transport http http://&lt;this-firewall&gt;:8500/mcp \
  --header "Authorization: Bearer &lt;auth-token-above&gt;"</pre>
    </div>
</div>
