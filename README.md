Full sequence to rebuild the `GOAD` range for `REDPILLS-range`.

Currently the Range is managed through Jenkins externally. This is accessible through the ranger VM.
On the Jenkins website, there are pipelines built that manage range deployment, agent runs and artifact collection.
Below details each pipeline and how they work.

### REDPILLS-RESET
This pipeline is responsible for tearing down the range and building a new deployment. Through the usage of `Bailey`,
a completely new topology will be built based off a spec and catalog file. This deployment takes around 2-3 hours
thus it is best to run in downtimes when no testing needs to be done. After the pipeline runs, the build will contain
the files from the deployment. These include deployment logs and errors that may have arose during deployment along with
config and topology information.

To note, sometimes due to stalling or issues with reaching the LUDUS API, errors may occur during range deployment. Please
double check the error logs. In general though, this build should be stable and range resets should have no issue.

### REDPILLS-create-snapshot
After a reset of the range, use this pipeline to create a snapshot of the range. It will prompt for a name for the snapshot and
a potential description. This snapshot will be used to rollback to the current topology in the next step.

### REDPILLS-episode
This pipeline is responsible for the majority of the pipeline. Before running, it will prompt for a snapshot and potentially a seed.
The snapshot is optional and can be skipped if `SKIP_SNAPSHOT_REVERT` is checked. If loading from a snapshot, the Range will revert
to what it looks like right after being reset.

From here, the pipeline will run `scenario_gen.py` on the topology and randomly generate CVEs and Flags onto hosts. This will sometime error out
due to stalling but should be stable on current range topologies, so rerun the pipeline if it fails.

After this, the pipeline will then pull the REDPILLS agent run it against the range by moving it to the kali box. After this step is completed, 
all the artifacts regarding the run, such as the episode directory, artifacts from hosts, and files documenting the state of the range will be
stored on the build under the artifacts and can be downloaded.
