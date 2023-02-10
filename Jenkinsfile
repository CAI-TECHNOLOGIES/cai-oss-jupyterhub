pipeline {
    agent {
        label 'k8agent'
    }
    options {
        skipStagesAfterUnstable()
    }
    stages {
        stage('Clone repository') {
            steps {
                script {
                    container('build-agent') {
                        checkout scm
                    }
                }
            }
        }
        stage('Build docker image') {
            steps {
                script {
                    container('build-agent') {
                        app = docker.build('lib')
                    }
                }
            }
        }
        stage('Store files') {
            steps {
                script {
                    container('build-agent') {
                        app.withRun(){ c ->
                            sh "docker cp ${c.id}:/src/jupyterhub/wheelhouse /base/build"
                        }
                    }
                }
            }
        }
    }
}