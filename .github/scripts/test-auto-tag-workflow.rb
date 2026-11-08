require 'json'
require 'open3'
require 'tmpdir'
require 'yaml'

def check(condition, message)
  abort "FAIL #{message}" unless condition
end

doc = YAML.load_file(ARGV.fetch(0))
job = doc.fetch('jobs').fetch('auto-tag')
steps = job.fetch('steps')
gate = steps.first
check(gate.fetch('name') == 'Verify all CI checks passed', 'verification must run first')
gate_id = gate.fetch('id')
check(job.fetch('if') == 'github.event.workflow_run.head_repository.full_name == github.repository',
      'job must be guarded to same-repository workflow_run events')
guard = "steps.#{gate_id}.outputs.decision == 'tag'"
release_steps = steps[1...-1]
check(release_steps.map { |step| step.fetch('name') } == [
  'Generate GitHub App token', 'Checkout', 'Install git-cliff',
  'Compute next version', 'Generate changelog, commit, tag, and push'
], 'all release operations must be covered')
release_steps.each do |step|
  expected = guard
  expected += " && steps.version.outputs.skip != 'true'" if step['id'] == 'release'
  check(step.fetch('if', nil) == expected, "#{step.fetch('name')} must require tag permission")
end

summary = steps.last
check(summary.fetch('name') == 'Job summary', 'summary must run last')
check(summary.fetch('if') == 'always()', 'summary must run for every gate outcome')
check(summary.fetch('env').fetch('GATE_DECISION') == "${{ steps.#{gate_id}.outputs.decision }}",
      'summary must consume the gate decision')
check(summary.fetch('env').fetch('GATE_REASON') == "${{ steps.#{gate_id}.outputs.reason }}",
      'summary must consume the gate reason')
puts 'ok   normalized workflow gates every release operation and propagates gate outputs'

required = ['Build and Test', 'golangci-lint', 'govulncheck', 'Lint Workflows', 'Lint Markdown']
trigger = (doc['on'] || doc[true]).fetch('workflow_run').fetch('workflows')
check(trigger.sort == required.sort, 'workflow_run triggers must cover the five workflows required by CONTRIBUTING.md')

runs = JSON.parse(STDIN.read)
check(gate.fetch('env').fetch('TRIGGER_RUN') == '${{ toJSON(github.event.workflow_run) }}',
      'gate must consume the triggering workflow run event')
scenarios = required.flat_map do |name|
  event = runs.find { |run| required.include?(run['name']) && run['name'] != name }
  [
    ['in_progress', nil, 'skip', 0, 3],
    ['completed', 'failure', 'no-tag', 1, 1]
  ].map do |status, conclusion, expected, exit_code, calls|
    input = runs.map do |run|
      run['name'] == name ? run.merge('status' => status, 'conclusion' => conclusion) : run
    end
    [name, [input], event, expected, exit_code, calls]
  end
end
scenarios << [nil, [runs], runs.find { |run| run['name'] == 'Lint Workflows' }, 'tag', 0, 1]

name = 'golangci-lint'
rerun_success = runs.find { |run| run['name'] == name }.merge('run_attempt' => 2)
rerun_failure = rerun_success.merge('conclusion' => 'failure')
stale_failure = runs.map { |run| run['name'] == name ? run.merge('conclusion' => 'failure') : run }
current_success = runs.map { |run| run['name'] == name ? rerun_success : run }
current_failure = runs.map { |run| run['name'] == name ? rerun_failure : run }
scenarios += [
  [name, [stale_failure, current_success], rerun_success, 'tag', 0, 2],
  [name, [stale_failure], rerun_success, 'tag', 0, 3],
  [name, [runs, current_failure], rerun_failure, 'no-tag', 1, 2],
  [name, [runs], rerun_failure, 'no-tag', 1, 3]
]

[rerun_success, rerun_failure].each do |event|
  expected, exit_code = event['conclusion'] == 'success' ? ['tag', 0] : ['no-tag', 1]
  current = runs.map { |run| run['name'] == name ? event : run }
  conflicting = event.merge('conclusion' => event['conclusion'] == 'success' ? 'failure' : 'success')
  lagging = [
    runs.reject { |run| run['name'] == name },
    runs.map { |run| run['name'] == name ? event.merge('id' => run['id'] - 1) : run },
    runs,
    runs.map { |run| run['name'] == name ? event.merge('status' => 'in_progress', 'conclusion' => nil) : run },
    runs.map { |run| run['name'] == name ? conflicting : run }
  ]
  lagging.each do |snapshot|
    scenarios << [name, [snapshot, current], event, expected, exit_code, 2]
    scenarios << [name, [snapshot], event, expected, exit_code, 3]
  end
end
scenarios << [name, [stale_failure], rerun_success.merge('event' => 'pull_request'), 'no-tag', 1, 1]
scenarios << [name, [stale_failure], rerun_success.merge('head_branch' => 'feature'), 'no-tag', 1, 1]

Dir.mktmpdir('auto-tag-test-', __dir__) do |directory|
  scenarios.each do |name, snapshots, event, expected, exit_code, calls|
    responses = File.join(directory, 'responses.json')
    File.write(responses, JSON.generate(snapshots.map { |input| [{ 'workflow_runs' => input }] }))
    gh_calls = File.join(directory, 'gh-calls')
    File.write(gh_calls, '')
    output = File.join(directory, 'outputs')
    File.write(output, '')
    env = {
      'SHA' => '52034ab2f35bd04a7b91f1a044284a234399c688',
      'REPOSITORY' => 'andrewesweet/spnego-proxy',
      'GITHUB_OUTPUT' => output,
      'TRIGGER_RUN' => JSON.generate(event),
      'TEST_API_RESPONSES' => responses,
      'TEST_GH_CALLS' => gh_calls
    }
    stubs = <<~'BASH'
      sleep() { :; }
      gh() {
        local call
        call=$(wc -l < "$TEST_GH_CALLS")
        jq -c --argjson call "$call" '.[$call] // .[-1]' "$TEST_API_RESPONSES"
        echo served >> "$TEST_GH_CALLS"
      }
    BASH
    stdout, stderr, result = Open3.capture3(env, 'bash', '-euo', 'pipefail', '-c', stubs + gate.fetch('run'))
    check(File.readlines(gh_calls).length == calls, "#{expected} must use #{calls} API calls: #{stdout}#{stderr}")
    check(result.exitstatus == exit_code, "#{expected} exit status: #{stdout}#{stderr}")
    outputs = File.readlines(output, chomp: true).map { |line| line.split('=', 2) }.to_h
    check(outputs['decision'] == expected, "#{expected} decision output")
    reason = expected == 'tag' ? 'all required workflows succeeded' : name
    check(outputs['reason'] == reason, "#{expected} reason output")

    report = File.join(directory, 'summary')
    File.write(report, '')
    summary_env = summary.fetch('env').to_h do |key, expression|
      value = case expression
              when "${{ steps.#{gate_id}.outputs.decision }}" then outputs.fetch('decision')
              when "${{ steps.#{gate_id}.outputs.reason }}" then outputs.fetch('reason')
              when '${{ steps.version.outputs.version }}' then 'v1.3.9'
              when '${{ steps.version.outputs.skip }}' then 'false'
              when '${{ steps.version.outputs.skip_reason }}' then ''
              when '${{ steps.release.outputs.pushed }}' then expected == 'tag' ? 'true' : ''
              else abort "FAIL unrecognized summary input: #{expression}"
              end
      [key, value]
    end
    _, stderr, result = Open3.capture3(summary_env.merge('GITHUB_STEP_SUMMARY' => report),
      'bash', '-euo', 'pipefail', '-c', summary.fetch('run'))
    check(result.success?, "#{expected} summary exit status: #{stderr}")
    expected_summary = case expected
                       when 'skip' then "Skipped: required CI not complete yet: #{name}."
                       when 'no-tag' then "No tag created: CI did not succeed: #{name}."
                       when 'tag' then "Tagged and pushed **v1.3.9**.\nThe release pipeline will now build and publish the release."
                       end
    check(File.read(report) == "### Auto Tag\n#{expected_summary}\n", "#{expected} summary contents")
    puts "ok   #{name || 'all required workflows'} attempt #{event.fetch('run_attempt')} -> #{expected}: #{calls} API calls, outputs and summary"
  end
end
