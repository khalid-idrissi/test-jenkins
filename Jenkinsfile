pipeline {
    agent any
    environment {
		netboxtoken = credentials('netboxtoken')
		tokenpywire = credentials('tokenpywire')
    }
    stages {
        stage('Intsall Packages') {
            steps {
				echo "Intsall Packages"
				bat 'pip install requests'
				bat 'pip install slugify'
            }
        }
        stage('Test') {
            steps {
                echo 'testing'
                bat "python jenkins.py ${netboxtoken} ${tokenpywire}"

            }
        }
    }
}