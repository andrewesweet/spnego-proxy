require 'json'
require 'open3'
require 'tmpdir'
require 'yaml'

def check(condition, message)
  abort "FAIL #{message}" unless condition
end

steps = YAML.load_file(ARGV.fetch(0)).fetch('jobs').fetch('auto-tag').fetch('steps')
gate = steps.first
check(gate.fetch('name') == 'Verify all CI checks passed', 'verification must run first')
gate_id = gate.fetch('id')
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

runs = JSON.parse(STDIN.read)
required = ['Build and Test', 'golangci-lint', 'govulncheck', 'Lint Workflows', 'Lint Markdown']
scenarios = required.map { |name| [name, 'in_progress', nil, 'skip', 0] }
scenarios += [
  ['govulncheck', 'completed', 'failure', 'no-tag', 1],
  [nil, nil, nil, 'tag', 0]
]

Dir.mktmpdir('auto-tag-test-', __dir__) do |directory|
  scenarios.each do |name, status, conclusion, expected, exit_code|
    input = runs.map do |run|
      run['name'] == name ? run.merge('status' => status, 'conclusion' => conclusion) : run
    end
    output = File.join(directory, 'outputs')
    File.write(output, '')
    env = {
      'SHA' => '52034ab2f35bd04a7b91f1a044284a234399c688',
      'REPOSITORY' => 'andrewesweet/spnego-proxy',
      'GITHUB_OUTPUT' => output,
      'TEST_API_RESPONSE' => JSON.generate([{ 'workflow_runs' => input }])
    }
    stdout, stderr, result = Open3.capture3(env, 'bash', '-euo', 'pipefail', '-c',
      "gh() { printf '%s\\n' \"$TEST_API_RESPONSE\"; }\n" + gate.fetch('run'))
    check(result.exitstatus == exit_code, "#{expected} exit status: #{stdout}#{stderr}")
    outputs = File.readlines(output, chomp: true).map { |line| line.split('=', 2) }.to_h
    check(outputs['decision'] == expected, "#{expected} decision output")
    check(outputs['reason'] == (name || 'all required workflows succeeded'), "#{expected} reason output")

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
    puts "ok   #{name || 'all required workflows'} -> #{expected}: outputs and summary"
  end
end
